# Bhaskix — Memory Management

*Status: draft for review. Owner: TBD. Prerequisite reading: [architecture.md](architecture.md).*

Covers physical frame allocation, virtual address spaces, the kernel heap, and the DMA/IOMMU path.
Target: `x86_64`, 4-level paging, with LA57 parameterised but untested (see open decision A5).

---

## 1. Boot-time memory bring-up

Four stages, in order. Each one exists because the next one cannot bootstrap itself.

```
1. Handoff memory map        bhaskix_boot::Handoff.memory_map — regions + types
2. Bump allocator            allocates the frame database, and nothing else
3. Buddy allocator           the real PMM, initialised from the frame database
4. Slab allocator            kernel heap, backed by buddy, exposed as GlobalAlloc
```

**Stage 2 is throwaway by design.** The bump allocator is a pointer and a limit. It carves the
`Frame` database out of the largest usable region, is used for nothing else, and is marked
permanently unavailable in stage 3. It has no `free`. Attempting to add one is a review rejection —
the whole point is that it cannot develop bugs.

**Memory region types** we care about from the handoff, and what we do with each:

| Type | Action |
|---|---|
| `Usable` | Hand to the buddy allocator |
| `BootloaderReclaimable` | Reclaimed *after* we stop reading the handoff — not before |
| `KernelAndModules` | Reserved; already mapped |
| `Framebuffer` | Reserved; mapped write-combining |
| `AcpiReclaimable` | Reserved until ACPI tables are parsed and copied, then released |
| `AcpiNvs`, `Reserved`, `BadMemory` | Never touched |

The single most common bring-up bug is reclaiming `BootloaderReclaimable` while a `&'static` slice
still points into it. We copy everything we need out of the handoff into kernel-owned memory in
`kernel::init::consume_handoff()`, and only then reclaim. The `Handoff` struct is moved into that
function and is not accessible afterwards — the borrow checker enforces what a comment would not.

---

## 2. Physical memory manager

### Choice: buddy allocator, not a bitmap

A bitmap is simpler and is what most tutorials use. We use a **buddy allocator** because contiguous
physical memory is a hard requirement we know is coming, not a maybe:

- DMA buffers for NVMe, virtio, and NICs need physically contiguous, alignment-constrained runs.
- Huge pages (2 MiB, 1 GiB) need naturally aligned contiguous blocks.
- VM domains need large contiguous backing for EPT efficiency.

Retrofitting contiguity onto a bitmap allocator means writing a buddy allocator later anyway, on top
of a system that has already fragmented.

### Structure

```rust
pub struct Pmm {
    zones: [Zone; MAX_ZONES],     // DMA32 (<4 GiB), Normal
    frames: &'static mut [Frame], // the frame database, one entry per physical frame
}

pub struct Zone {
    free_lists: [FreeList; MAX_ORDER + 1],  // orders 0..=10  → 4 KiB .. 4 MiB
    lock: SpinLock<()>,
    free_pages: AtomicUsize,
}

#[repr(C)]
pub struct Frame {
    order: u8,
    flags: FrameFlags,       // Free | Allocated | Buddy head | Pinned | Reserved
    refcount: AtomicU32,     // for shared / COW frames
    owner: DomainId,         // accounting — which domain is charged for this frame
}
```

`Frame` is kept small and cache-line-friendly; it is indexed by PFN, so `frame_of(pa) =
&frames[pa >> 12]` is a shift and an add.

### Per-CPU magazines

Order-0 allocation is the hot path and a global zone lock on it will not survive SMP. Each CPU keeps
a small magazine of free order-0 frames (target 32, refilled/drained in batches of 16 under the zone
lock). Allocation and free are lock-free in the common case.

Trade-off accepted: up to `ncpus × 32` frames are invisible to the global free count. Reclaim drains
magazines before it declares memory pressure.

### `DMA32` zone

Some devices cannot address above 4 GiB. We keep a separate zone rather than discovering this at the
worst possible moment. Allocation policy: normal allocations prefer `Normal` and never fall back
*into* `DMA32`; `DMA32` allocations may fall back to... nothing. If `DMA32` is exhausted, the request
fails. Silently satisfying a 32-bit DMA request with a 64-bit frame produces memory corruption that
looks like a driver bug for weeks.

### Ownership and accounting

Every allocated frame records its owning `DomainId`. This gives us, for free:

- Per-domain memory limits enforced at allocation time (the `ResourceEnvelope`).
- Exact accounting for the telemetry plane — no sampling, no estimation.
- Correct cleanup on domain teardown: walk the frame database, free everything owned.

---

### Per-CPU frame reserves for the fault path

**Implemented at M4-12.** Servicing a page fault means allocating — a frame for the page, sometimes
more for the page-table levels above it — and allocating means taking the physical allocator's lock.
A page fault can interrupt *anything*, including code on the same CPU that already holds that lock,
so the fault handler must never wait for it.

Each CPU therefore keeps a small reserve of frames it has already taken, and the fault path spends
those. Refilling happens from the timer interrupt, a context that can afford to fail and try again.

The reserve needs **no lock at all**, and that is the point rather than an optimisation: a CPU's
reserve is touched only by that CPU, so the only concurrency is an interrupt arriving mid-update,
and interrupts are masked for the few instructions involved. This is
[architecture.md](architecture.md) §6's "prefer per-CPU over shared" applied where every alternative
design ends in a lock the fault handler must not wait for.

What it does not do:

- **It is not a memory guarantee.** A reserve that runs dry means the fault is refused, exactly as
  before. It converts a likely failure into a rare one, and the boot report counts the misses so the
  difference is visible rather than assumed.
- **It does not survive a burst** beyond its size between refills. Sizing it against a real fault
  rate needs a workload that generates one.
- **Reserved frames are not free memory**, and every leak check accounts for them separately —
  otherwise the project's most trusted gate would report a refill as a leak, and be believed.

Gated by a test that holds the allocator's real lock and then faults inside it. Negative-tested:
emptying the reserve makes that fault report `no frame in this cpu's reserve` and the gate goes red.

---

## 3. Virtual memory

### `AddressSpace`

```rust
pub struct AddressSpace {
    root: PhysAddr,              // PML4 frame
    asid: Option<Asid>,          // PCID on x86_64, when available
    regions: RangeMap<VmRegion>, // sorted, non-overlapping
    domain: DomainId,
}

pub struct VmRegion {
    range: VirtRange,
    prot: Protection,            // R / W / X — never W and X together
    backing: Backing,            // Anonymous | File{..} | Device{..} | Shared{..}
    flags: RegionFlags,          // COW | Locked | Guard | Growable
}
```

The `RangeMap` is the source of truth; the page table is a *cache* of it. On a page fault we consult
the `RangeMap` to decide whether the fault is legal, then populate the page table. This is what makes
demand paging, COW, and file-backed mappings uniform instead of three special cases.

### W^X is absolute

`Protection` cannot represent write+execute. There is no flag to override it, no boot parameter, and
no `mprotect` path that reaches it. JIT workloads use two mappings of the same frames with different
protections — the standard modern approach, and one that keeps the invariant checkable by inspection
rather than by audit.

NX must be enabled (`EFER.NXE`) before the first mapping is created. If the CPU does not support NX,
we refuse to boot. A 64-bit CPU without NX does not exist in our target set, and supporting the
hypothetical costs us a real guarantee.

### Page fault handling

```
fault(addr, error_code)
  ├─ addr in kernel range and we are in user mode  → kill domain
  ├─ no region contains addr                        → segfault / kill
  ├─ write to a read-only region                    → segfault
  ├─ write to a COW region                          → copy frame, remap RW, return
  ├─ not-present in a demand-paged region           → allocate/read, map, return
  ├─ addr in a guard page                           → stack overflow: kill with a clear message
  └─ fault in kernel mode outside a fixup region    → PANIC, dump state
```

The last line matters. A kernel-mode fault at an address the kernel had no business touching is
always a bug, and it must be loud. The only exception is *fixup regions*: code that copies to or from
user memory registers itself in a fixup table, so a bad user pointer produces `EFAULT` rather than a
panic. This is the `copy_from_user` / `copy_to_user` mechanism, and it is the only sanctioned way
kernel code touches user memory.

### Copy-on-write

Fork-style COW is refcount-based on the `Frame`. Rules:

- Sharing a frame increments `refcount` and makes *all* mappings read-only.
- A write fault with `refcount == 1` just remaps writable — no copy. (Missing this optimisation makes
  fork-heavy workloads allocate twice as much as they need.)
- A write fault with `refcount > 1` allocates, copies, decrements, remaps.
- Frame free happens at `refcount == 0`, not on first unmap.

### TLB shootdown

Unmapping or downgrading a mapping in an address space that is active on other CPUs requires an IPI.
The naive implementation (IPI on every unmap, wait for all) is correct and slow; we start there and
measure. Batching and per-CPU generation counters come after there is something to measure. This is
written down so that nobody "optimises" it in month two based on intuition.

PCID/ASID support avoids full flushes on context switch. It is an optimisation, not a correctness
requirement, and is gated behind a CPU feature check.

---

## 4. Kernel heap

A **slab allocator** over the buddy allocator, exposed as Rust's `GlobalAlloc` so that `alloc`
(`Box`, `Vec`, `BTreeMap`) works in the kernel.

- Size classes: 16, 32, 64, 128, 256, 512, 1024, 2048 bytes. Larger goes straight to buddy.
- Per-CPU caches per size class, same magazine approach as the PMM.
- Every slab page is a buddy allocation with a header; freeing finds the header by masking the
  pointer, so `dealloc` does not need a size lookup.
- **Guard the allocator against itself:** slab metadata lives in a separate allocation from the
  objects, so an object overflow corrupts data rather than the allocator's own free list. This costs
  a little memory and removes a category of bug that is exceptionally hard to debug.

Debug builds add: red-zone bytes around allocations, poison on free (`0xDE`), and delayed reuse
(quarantine) to catch use-after-free. These are compile-time features, off in release.

**No allocation in these contexts**, enforced by the `SleepGuard` marker described in
[architecture.md](architecture.md) §6:

- Interrupt handlers
- Inside the PMM zone lock
- The context switch path
- Panic handling (the panic path uses a pre-reserved static buffer)

---

## 5. DMA and the IOMMU

This section is a security boundary, not a performance one. See [security.md](security.md).

A device that can perform DMA can, by default, read and write all of physical memory — including the
kernel. This defeats every software isolation guarantee we make. Therefore:

**Every DMA-capable device is behind the IOMMU (VT-d / AMD-Vi), including in-nucleus drivers.**

```rust
pub struct DmaWindow {
    domain: IommuDomain,      // per-device IOMMU page tables
    cap: DmaCapability,       // what the driver was granted
}

impl DmaWindow {
    pub fn map(&mut self, buf: &DmaBuffer, dir: Direction) -> Result<DevAddr>;
    pub fn unmap(&mut self, dev: DevAddr);
}
```

- A driver receives a `DmaCapability` naming exactly the frames it may map. It cannot widen it.
- Device addresses (`DevAddr`) are a distinct type from `PhysAddr`. They are not interchangeable and
  the compiler will say so.
- Unmapping invalidates the IOMMU TLB before returning. A stale IOMMU entry is a live exploit.
- If the platform has no IOMMU, Bhaskix boots in a degraded mode that is **reported in the attestation
  log and printed at boot**. We do not silently accept a broken threat model.

Bounce buffering for devices with addressing limits is handled in the DMA layer, not in each driver.

---

## 6. Memory pressure and reclaim

Deferred to Phase 2, specified now so that Phase 1 data structures do not preclude it.

- Reclaim is per-domain first (a domain over its envelope reclaims from itself), global second.
- Reclaim order: clean file-backed pages → drain per-CPU magazines → compact for contiguity →
  swap (Phase 3) → OOM-kill the domain with the worst envelope overrun.
- The OOM decision is one of the **pluggable policies** described in [ai-native.md](ai-native.md).
  The default is a deterministic scoring heuristic; an AI policy may reorder candidates but may
  never nominate a candidate the heuristic ruled ineligible (init, the AI daemon itself, any domain
  holding a reclaim-critical lock).

---

## 7. Testing strategy

Memory management is the subsystem where a bug costs the most debugging time, so it gets the most
test infrastructure, built before the code:

| Layer | How |
|---|---|
| Buddy allocator | Host unit tests. It is pure logic over a synthetic frame database — no hardware needed. Property test: any sequence of alloc/free leaves the free-list invariants intact and loses no frames. |
| Slab | Host unit tests, same approach, plus a fuzz target on alloc/free sequences. |
| `RangeMap` | Host unit tests. Property test: regions never overlap; split/merge round-trips. |
| Page tables | Host tests against a simulated page-table walker, then QEMU. |
| Fault handling | QEMU integration tests, one test per branch of the fault decision tree above. |
| TLB/IOMMU | QEMU with `-device intel-iommu`, multi-CPU. |

**The frame-leak test is a gate:** a QEMU test boots, runs a workload that creates and destroys 1000
domains, and asserts the free frame count returns to its starting value. It runs on every PR. Memory
leaks in a kernel are found this way or not at all.

---

## 8. Open questions

- **A5 (from architecture.md):** LA57. Parameterise now or assume 4-level?
- Should the HHDM be unmapped in user-facing paths (KPTI-style) from the start? It costs performance
  and buys Meltdown-class mitigation. Current lean: no, but keep the page tables split-capable.
- Huge page policy: transparent promotion, explicit only, or both? Transparent huge pages are a
  well-known source of latency spikes; "explicit only" is the safer default for an enterprise OS.
- Frame database for sparse/hotplug memory: flat array is simple and wastes memory on sparse maps.
  Revisit if a target platform needs it.
