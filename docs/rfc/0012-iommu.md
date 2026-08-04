# RFC 0012: The IOMMU, and what a device is allowed to reach

| | |
|---|---|
| **Status** | **Draft — for discussion.** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`iommu`, `cap`), arch (`acpi`, `pci`), mm |
| **Milestone** | Phase 3 in [roadmap.md](../roadmap.md) — argued below that discovery and per-device domains should move to Phase 2 |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (the `Memory` object this maps), [RFC 0011](0011-irq-handler.md) (which is blocked on this), [memory.md](../memory.md) §5, [security.md](../security.md) §1 T3 and T4 |

---

## Summary

Program the platform's IOMMU so that **a device can reach only the memory it
has been given**, and give it that memory through the same `Memory` object
RFC 0009 defines.

A `DmaWindow` capability names a device's address space. Its one interesting
method maps a `Memory` object into that space and returns a **`DevAddr`** — a
type distinct from `PhysAddr`, which drivers hand to devices instead of the
physical addresses they hand them today.

This is the prerequisite [RFC 0011](0011-irq-handler.md) names and does not
remove, and it closes two threats `security.md` §1 already claims to defend
against and currently does not.

---

## Motivation

**Two of the ten in-scope threats are unfunded.** `security.md` §1 lists:

| | Threat | Stated mitigation |
|---|---|---|
| **T3** | A compromised or malicious device driver | "IOMMU-enforced DMA windows" |
| **T4** | A malicious peripheral performing DMA | "IOMMU on by default; devices default-denied" |

Neither exists. Since RFC 0009 the kernel at least *says so* at boot —

```
    dma            NO IOMMU: this device can reach all of physical memory (docs/memory.md §5)
```

— which is `memory.md` §5's requirement met and the threat unaddressed. A
document that names a mitigation the code does not have is worse than one that
admits the gap, and this project has now printed the admission in every boot
log for a milestone.

**A user-mode driver is impossible without it.** RFC 0011 delivers interrupt
delegation and states plainly that giving a domain a device still gives it the
machine. Every step of that RFC's plan except the last is useful without an
IOMMU; the last one cannot be taken.

**An in-nucleus driver's mistakes are unbounded.** M6-06's `virtio-blk` writes
physical addresses into descriptors the device dereferences with nothing in
between. TRACKER records it as "the one operation in this kernel that no page
table can contain". That is true, and an IOMMU is the thing that makes it
false.

**Phase placement.** [roadmap.md](../roadmap.md) puts "IOMMU — full
VT-d/AMD-Vi, per-device domains" in Phase 3. This RFC proposes splitting it:
**discovery, per-device domains and strict mapping belong in Phase 2**,
because they are what make a driver's bugs containable and what unblock RFC
0011; interrupt remapping and nested translation for VMs can stay in Phase 3.
The full item is a Phase 3 amount of work; the part that changes the threat
model is not.

---

## Design

### What the hardware is

Both x86-64 IOMMUs work the same way at the level that matters: a table
indexed by the device's bus/device/function selects a page table, and every
DMA the device performs is translated through it. Untranslatable means the
access is refused and a fault is reported.

| | Intel VT-d | AMD-Vi |
|---|---|---|
| Described by | `DMAR` ACPI table | `IVRS` ACPI table |
| Per-device selector | Root table → context table | Device table |
| Translation | Second-level page tables | I/O page tables |
| Invalidation | Queued invalidation, or register | Command buffer |
| Interrupt remapping | Yes, same unit | Yes, same unit |

**This RFC specifies VT-d first**, with the interfaces below shaped so AMD-Vi
is an implementation of them rather than a second design. The reason is
testability: QEMU emulates VT-d (`-device intel-iommu`), so every gate here
can run in CI, and a design that cannot be tested in CI is a design that will
be wrong in ways nobody notices.

**An AMD machine therefore boots in degraded mode until AMD-Vi lands**, and
says so in the same line the missing-IOMMU case uses today. That is a real gap
with a real cost and it is stated rather than glossed.

### The objects

```rust
/// A device's address space: what one device (or a group) may reach.
pub struct DmaWindow {
    devices: DeviceList,          // bus/device/function this window translates for
    table: IoPageTable,           // the second-level tables
    allocator: DevAddrSpace,      // which DevAddrs are free
    owner: DomainId,
}

/// An address a *device* uses. Not a PhysAddr, and the compiler says so.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevAddr(u64);
```

| Capability | Method | Effect |
|---|---|---|
| `IommuControl` | `WINDOW(device)` | Create a `DmaWindow` for a device, default-deny |
| `DmaWindow` | `MAP(memory, rights)` | Map a `Memory` object; returns a `DevAddr` |
| `DmaWindow` | `UNMAP(devaddr)` | Remove it, invalidating before returning |
| `DmaWindow` | `INFO` | What is mapped, and how much |

`IommuControl` is the same shape as RFC 0011's `IrqControl` — one privileged
capability, held by the initial domain, that hands out the per-device ones.
The two RFCs' root capabilities and the eventual device object want to be
handed out together, and *Unresolved questions* says so.

### It composes with RFC 0009 rather than duplicating it

A driver's buffer is a `Memory` object. RFC 0009 lets its owner map it into
its own address space; this RFC lets the owner of a `DmaWindow` map the same
object into a device's. One object, two mappings, one place that owns the
frames and one envelope charged for them.

That composition is the reason this RFC is short. It also gives revocation for
free in the direction that matters most: **revoking the `Memory` capability
unmaps it from the device too**, because RFC 0009's reverse map gains device
mappings as a second kind of entry, and its rule — mappings first, then
capabilities — already forbids the window where the capability is dead and the
memory is still reachable.

A device mapping is exactly the case that makes RFC 0009's `MAX_MAPPINGS`
bound worth having: a revocation that must complete cannot iterate an
unbounded list, and it must now also invalidate an IOTLB per entry.

### Default deny, and the boot sequence that makes it survivable

Every device gets its own window with **nothing mapped**. That is
`driver-model.md` §5's "an unmatched device gets no capabilities and is left
in reset", enforced by hardware rather than by the driver framework's
politeness.

Enabling translation on a running machine is the part that breaks real
hardware, and it breaks it in a way an emulator will not show:

1. **Firmware-reserved regions.** VT-d's `RMRR` (and AMD's `IVMD`) name
   physical regions that specific devices must keep reaching — legacy USB
   keyboard emulation, and a graphics device's framebuffer, are the usual two.
   A kernel that enables translation without identity-mapping them wedges the
   keyboard on the machines that need it most.
2. **Devices already doing DMA.** A device the firmware or bootloader left
   running takes a fault the instant translation is enabled. The sequence is:
   build every window, identity-map the reserved regions, *then* enable, and
   expect faults during the transition and report them rather than panic.
3. **The IOMMU's own interrupt.** Fault reporting needs a vector, which is
   RFC 0011's allocator, which is why that RFC's steps 1–4 come first.

### Faults are the feature, not an error path

An IOMMU fault means a device attempted an access it was not granted. That is
either a driver bug or a hostile device, and it is precisely the event this
whole RFC exists to make visible.

```
on_iommu_fault:
    read the fault record: device, DevAddr, read/write, reason
    count it, per device
    report it: the device, what it reached for, and the driver that owns it
    clear the fault register
```

**A fault is never silently dropped.** The count is a boot-gate assertion —
zero in normal operation — and a deliberately wrong descriptor address is the
negative test, which is the strongest test in this RFC: the driver asks the
device to write somewhere it was not given, and the machine reports it instead
of corrupting a page.

### Invalidation is strict, and that is a decision with a cost

`memory.md` §5: *"Unmapping invalidates the IOMMU TLB before returning. A
stale IOMMU entry is a live exploit."*

Linux offers a deferred mode that batches invalidations and is measurably
faster, at the cost of a window in which a freed page is still device-
reachable. **This RFC keeps the strict rule**, because the whole value of the
mechanism is that "after unmap returns" is a statement you can build on — the
same argument RFC 0009 makes about revocation, arriving from the hardware
side.

The cost is real and will be measured rather than assumed: an invalidation is
a queued command and a wait for its completion, and the measurement is in
*Performance implications*.

### Interrupt remapping, and what it does to RFC 0011

The same hardware unit can remap interrupts: with it enabled, a device's MSI
carries an *index* into a kernel-owned table rather than a vector. A device
that lies — or is programmed by something that lies — can then only raise
interrupts its table entries permit.

RFC 0011 keeps MSI-X programming in the kernel precisely because an MSI is an
arbitrary-vector write. Interrupt remapping does not replace that rule; it
makes the rule survive a device that ignores what it was programmed with.
**Proposal: enable interrupt remapping in the same work, and treat RFC 0011's
kernel-only MSI-X programming as the belt to its braces.**

### Bounce buffering

`memory.md` §5: *"Bounce buffering for devices with addressing limits is
handled in the DMA layer, not in each driver."* With an IOMMU, a 32-bit device
is handled by allocating its `DevAddr` below 4 GiB — no copy at all. Bounce
buffering is then only needed on machines with **no** IOMMU, where it provides
addressing and no protection whatsoever, and where it must not be mistaken for
a mitigation.

### Concurrency

| Path | Locks | Context |
|---|---|---|
| `WINDOW` | the IOMMU unit's lock | thread, at device bring-up |
| `MAP` / `UNMAP` | the window's, then the invalidation queue | thread |
| fault handling | none beyond a register read | interrupt |

The invalidation queue is per-unit and is the one piece with a hardware
completion to wait for. Waiting for it inside the window lock is correct and
serialises unmaps on one device, which is the behaviour a strict rule implies.

### Failure behaviour

| Situation | Answer |
|---|---|
| No `DMAR` table | Degraded mode: reported at boot, and domain-hosted drivers refused |
| A `DMAR` table that does not parse | Same as absent, and counted as a firmware fault |
| `MAP` with no free `DevAddr` | Refused; nothing is programmed |
| `UNMAP` while an invalidation is outstanding | Serialised; the second waits |
| A device faulting during the enable transition | Reported, not fatal — see the boot sequence |
| The IOMMU reports a queue error | The unit is marked failed and every window on it refuses further maps. A half-working IOMMU is worse than none, because it is believed |
| A domain dies holding a `DmaWindow` | Every mapping removed and invalidated, then the window destroyed |

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Keep going without one** (status quo) | T3 and T4 are claimed in `security.md` and not delivered; user-mode drivers are impossible; an in-nucleus driver's wrong descriptor is unbounded. | — |
| **Identity-map everything** (`iommu=pt`) | Gives the addressing benefits and none of the protection, while making the boot log say an IOMMU is present. It is the mode most likely to be enabled by accident and mistaken for a mitigation. | As an explicit, reported, degraded mode for a machine whose IOMMU is broken — never as a default, and never silently. |
| **IOMMU only for domain-hosted drivers** | `memory.md` §5 says "including in-nucleus drivers", and an in-nucleus driver's bug is exactly the case M6-06's honest note is about. Exempting the drivers most likely to be written in a hurry is exempting the wrong ones. | Measurement showed the in-nucleus cost was prohibitive — in which case the answer is a faster invalidation strategy, not an exemption. |
| **Software bounce buffering only** | Solves addressing, not protection. A device still reaches everything; it just reaches a copy. | It is the fallback on machines with no IOMMU, and is described as addressing only. |
| **AMD-Vi first, or both at once** | QEMU emulates VT-d, so VT-d is the one whose gates can run in CI. Both at once doubles the work before either is tested. | An AMD machine becomes the primary development target — at which point this reverses, and the interfaces are shaped so it can. |
| **Deferred invalidation for speed** | `memory.md` §5 forbids it in one sentence, and the sentence is right: a stale entry is a live exploit. | Never for correctness-critical unmaps. Possibly for a batched teardown path where the whole window is destroyed and every entry is invalidated before any frame is reused. |
| **Wait for Phase 3, as the roadmap says** | Two claimed threat mitigations stay unfunded, and RFC 0011's last step stays blocked, for the length of Phase 2. | This is the decision being asked for. The proposal is to split the item, not to move all of it. |

---

## Impact on existing design documents

**[memory.md](../memory.md) §5** is the specification this implements, and it
was written before the code existed. Two things in it need revisiting rather
than merely implementing:

> `pub struct DmaWindow { domain: IommuDomain, cap: DmaCapability }`

The capability should not be *inside* the window — the window **is** the
object a capability names, which is how every other object in this kernel
works. And `DmaBuffer` should be RFC 0009's `Memory`, not a fourth kind of
memory region.

> "If the platform has no IOMMU, Bhaskix boots in a degraded mode that is
> **reported in the attestation log** and printed at boot."

There is no attestation log. The boot print exists since RFC 0009; the log is
Phase 3, and the sentence should say which half is real.

**[security.md](../security.md) §1** T3 and T4 stop being claims and become
statements, and the section should say from which milestone.

**[driver-model.md](../driver-model.md) §5's** "devices default-denied until
enumerated and granted" becomes hardware-enforced rather than a property of
the framework's behaviour.

**[roadmap.md](../roadmap.md) Phase 3** loses "per-device domains" to Phase 2
if this RFC's split is accepted, and keeps interrupt remapping and nested
translation.

---

## Security implications

**This RFC is the mitigation for two in-scope threats**, so its own security
section is mostly about how it can be wrong:

**A half-working IOMMU is worse than none.** If a unit is present but its
queue errors, or a device is not covered by any unit's scope, the kernel
believes memory is protected and it is not. Hence: any unit that reports a
queue error marks itself failed and refuses further maps, and a device covered
by no unit is treated as if there were no IOMMU at all — reported, and not
delegable.

**Firmware describes the hardware, and firmware is not trusted.** The `DMAR`
table is another untrusted parser, of the same kind as the ACPI walk M6-04
added. It gets the same treatment: bounded, checked, and a seeded mutation
harness — and unlike the MADT, believing it wrongly means programming a
register window that is not an IOMMU. **This is the fuzz target this RFC
adds.**

**Reserved regions are an attack surface by design.** An `RMRR` names memory a
device may always reach, and firmware chooses it. A firmware that named the
kernel's memory would be granting a device access to it. The kernel must
therefore *check* reserved regions against its own image and refuse to
identity-map anything that overlaps it — reporting the refusal, because a
machine whose firmware asked for that is a machine worth knowing about.

**What becomes reachable without a capability.** Nothing. Creating a window
needs `IommuControl`; mapping needs the window and the `Memory` capability.

**Interrupt remapping** closes the residual case in RFC 0011: a device that
raises an MSI it was not programmed to raise.

---

## Performance implications

**Slower:** every DMA mapping is now a page-table write plus an invalidation
with a hardware completion. Every device access is an IOTLB lookup, with a
miss walking the tables.

**Faster:** nothing. This is a protection mechanism and it costs what it
costs. The honest framing is that the cost buys T3 and T4, and the measurement
exists to say whether the cost is where anyone expected.

**What will be measured**, on the same machine, with the IOMMU on and off:

| Measurement | Why |
|---|---|
| `virtio-blk` requests per second | The end-to-end number anyone will quote |
| Time in `MAP` and in `UNMAP`, p50 and p99.9 | Where the strict-invalidation cost lands |
| Invalidation completions per second at saturation | Whether the queue is the bottleneck |
| IOTLB misses per request, if the hardware counts them | Whether the mapping strategy is wrong |

A driver that maps and unmaps per request will be dominated by invalidation. A
driver that maps a pool once and reuses it will not — and that difference is a
*driver* design rule that belongs in `driver-model.md`, discovered here.

---

## Testing plan

**On the host:**

- `DMAR` parsing: well-formed tables, truncated ones, a unit whose register
  base is implausible, scopes naming devices that do not exist. **The seeded
  mutation harness**, as `ustar`, `elf` and the MADT walk already have.
- Page-table construction: the second-level format, for every level and every
  page size, against known-good encodings.
- `DevAddr` allocation: exhaustion, reuse after unmap, and the below-4-GiB
  constraint for a 32-bit device.
- Reserved regions overlapping the kernel image are refused.

**In QEMU** — and this is the part that makes the RFC testable at all, with
`-device intel-iommu,intremap=on`:

- The IOMMU is found, programmed, and enabled, and `virtio-blk` still works.
  That single assertion covers discovery, windows, mapping, and translation.
- **The negative test that is the whole point:** a descriptor is deliberately
  given an address outside the device's window, and the machine reports an
  IOMMU fault naming the device — rather than the device writing to a page
  nobody expected. Before this RFC that test cannot even be written.
- The fault counter is zero across an otherwise normal boot.
- Frame-leak accounting across create-window / map / unmap / destroy.
- A machine with the IOMMU *absent* (`make test` as it runs today) keeps
  working and keeps printing the degraded line — so the degraded path stays
  exercised rather than rotting.

**On real hardware:** the first thing in this project whose behaviour will
differ substantially. Reserved regions, devices already doing DMA at enable
time, and firmware that describes units inaccurately are all real-hardware
phenomena that QEMU will not produce. M1-17's hardware boot becomes a
prerequisite for calling this done, rather than a parallel task.

---

## Unresolved questions

1. **One window per device, or one per driver?** A driver with several
   functions of the same device wants them sharing a window; two drivers must
   not. Proposal: per device, with a method to add a second device to an
   existing window, refused unless both are held by the same domain.
2. **Do in-nucleus drivers get their own windows, or one shared kernel
   window?** Separate is the point of T3; shared is cheaper. Proposal:
   separate, and measure.
3. **`IommuControl`, `IrqControl`, and the eventual device object** are three
   privileged capabilities that will always be handed out together. Whether
   they should be one object with three methods is a question for whichever
   RFC defines the device object, and it should not be answered three times.
4. **Nested translation** for VMs (Phase 3's virtualization) needs a second
   translation stage and interacts with EPT. Out of scope here, and the
   interfaces should not make it harder.
5. **ATS and device page faults** — devices that can take a page fault rather
   than requiring pinned memory. Proposal: no. Pinned mappings only, which is
   what a fixed `Memory` object already is.
6. **What a machine with no IOMMU may run.** Proposal: everything except a
   domain-hosted driver, reported at boot. The alternative — refusing to
   boot — makes the project unusable on the hardware most contributors have.

---

## Implementation plan

1. **Discovery and reporting.** Parse `DMAR`, find the units, report what was
   found — and replace today's unconditional "NO IOMMU" line with the truth.
   No translation is enabled. The mutation harness lands here.
2. **Windows and page tables**, with translation still disabled: build the
   structures for every device and prove them against known encodings on the
   host.
3. **Enable, with reserved regions identity-mapped** and the enable-time
   fault path. `virtio-blk` keeps working; the fault counter is zero.
4. **`MAP`/`UNMAP` and `DevAddr`,** with `virtio-blk` converted to hand the
   device a `DevAddr` rather than a `PhysAddr`. The negative test lands here:
   an address outside the window is a reported fault.
5. **RFC 0009 integration** — a `Memory` object mapped into a device window,
   and revocation unmapping from the device as well.
6. **Interrupt remapping**, which retires RFC 0011's residual risk.
7. **Delegation**: a `DmaWindow` capability to a domain, which is the step
   every one of RFC 0009, 0010 and 0011 has been building toward, and the
   first moment a driver can run outside the kernel.

Steps 1–4 change the threat model and are the Phase 2 argument. Steps 5–7 are
what the previous three RFCs were for.
