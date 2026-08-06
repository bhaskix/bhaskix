# RFC 0014: The driver framework, and what the second driver should not have to learn again

| | |
|---|---|
| **Status** | 📝 **Draft** — proposed 2026-08-06 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | arch (`pci`), kernel (`virtio`, `mmio`), a new `device` crate, userspace drivers |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) — the *driver framework* bullet |
| **Depends on** | [RFC 0011](0011-irq-handler.md) (a delegated interrupt), [RFC 0012](0012-iommu.md) (a delegated DMA window), [RFC 0013](0013-service-framework.md) (a driver in a domain, and `ATTACH`) |

---

## Summary

Two drivers exist for the same device. One is in the kernel and one is in a domain, they share no
code, and writing the second one cost an afternoon to three bugs the first one had **already
learned and written down in comments**.

This proposes the smallest framework that makes those three bugs unrepeatable rather than merely
documented: a typed MMIO accessor that cannot be used at the wrong width, a register-block macro so
offsets are declared once, ECAM so configuration space is memory rather than a pair of ports, and a
mock-MMIO harness so a driver's logic can be tested without a machine.

It also asks a question the port-I/O world could not: **with ECAM, a device's configuration space is
a page — so how much of it can a domain be given?**

---

## Motivation

### Three bugs, all of them already known

Writing `bin/blkd` — the block driver RFC 0013 step 6 put in a domain — cost the following, in
order, each one presenting as a device that said nothing at all:

1. **`queue_desc` written as one eight-byte store** instead of two four-byte ones. `virtio.rs`
   carries a three-line comment saying exactly why that is wrong. The new driver had its own
   `write64` and it did the obvious thing.
2. **Bus mastering never enabled.** `pci::enable`'s doc comment predicts the symptom word for word:
   *"its rings stay empty and every request times out — which reads as a broken device rather than
   as a missing bit"*.
3. **A context entry added to a live IOMMU with no context-cache invalidation.** Nobody had ever
   added a device to a translating unit before, so nothing had ever needed it.

The lesson recorded at the time was "a driver written beside a working one should be read against it
first". That is true and it is not a mechanism. A framework is the mechanism: **the second driver
should not be able to make the first driver's mistakes, whether or not anybody read the comments.**

### Two copies of the same primitives, which disagreed

`kernel/src/virtio.rs` and `user/blkd/src/main.rs` each hand-roll `read8`/`read16`/`read32`/`write8`
/`write16`/`write32`/`write64` over raw addresses — 56 uses in one, 42 in the other. They are the
same six functions written twice, and the two versions **disagreed about the one that mattered**.

A width is not a property of a call site. It is a property of the register, and it should be
declared where the register is.

### A driver's logic cannot be tested without a machine

`bin/blkd`'s virtqueue — descriptor chaining, the available ring, the fence before the index, the
used ring — is exercised only by booting QEMU with two disks attached. RFC 0013 made a service's
logic testable on the host by giving it a context of function pointers, and the first thing that
found was a placement disagreeing with itself about a refusal. A driver's logic deserves the same,
and MMIO is even easier to fake than a kernel: it is loads and stores to an address the harness
chooses.

### Enumeration is the reason the bus stayed in the kernel

RFC 0013 step 6 says: *"PCI configuration space is port I/O, and a domain holding that would hold
every device on the machine, so the kernel enumerates and the domain drives. The split is not a
convenience — it is where the hardware puts the line."*

That sentence is true of **port I/O** and not of PCIe. With ECAM, each function's configuration
space is 4 KiB of ordinary memory at a computable address, which is the same shape as every other
window a domain already holds. The hardware moved the line and this design has not noticed yet.

---

## Design

### `Mmio<T>` — a register, not an address

```rust
/// One memory-mapped register of width `T`.
pub struct Mmio<T> { at: *mut T }

impl Mmio<u32> { pub fn read(&self) -> u32; pub fn write(&self, value: u32); }
impl Mmio<u64> { pub fn read(&self) -> u64; pub fn write(&self, value: u64); }
```

The `u64` implementation reads and writes **two 32-bit halves, low first**, because that is what the
virtio specification defines and what a device model is entitled to notice. That is bug 1, fixed
once, in the only place that can be wrong.

Widths cannot be mixed by accident: a `Mmio<u16>` has no `read()` returning `u32`.

### `register_block!` — offsets declared once

```rust
register_block! {
    pub struct CommonCfg {
        0x00 => device_feature_select: u32,
        0x04 => device_feature: u32,
        0x12 => num_queues: u16,
        0x14 => device_status: u8,
        0x20 => queue_desc: u64,
    }
}
```

Expands to a struct of `Mmio<T>` built from one base address, with a compile-time assertion that no
two fields overlap and none leaves the block. Today those offsets are three copies of the same
constants (`virtio.rs`, `blkd`, and this RFC's example) with nothing checking they agree.

### `Device` — a handle you cannot hold without having enabled it

A driver receives a `Device`, and `Device::claim()` is the only way to make one. Claiming enables
memory space and bus mastering in the order RFC 0012 step 4 established: memory first, so the BARs
can be read; bus mastering **after** the device has been reset, so a device configured by firmware
does not do a stray DMA the instant translation is on.

That is bug 2, made structural: a driver that has a `Device` has a device that can do DMA, and there
is no way to have the one without the other.

### ECAM, and what a domain may hold of it

The kernel parses `MCFG`, and configuration access becomes a memory read. Enumeration stays in the
kernel — walking the bus discovers devices nobody has granted anybody — but a *function's* 4 KiB of
configuration space becomes something a `Frame` capability can name.

**Not all of it may be delegated**, and the split is not obvious:

| Field | Delegable? | Why |
|---|---|---|
| Vendor, device, class, capabilities list | read | Identification. Reading it grants nothing. |
| Command register | mediated | Bus mastering is DMA. Granting it means granting DMA, which RFC 0012 says needs a window first. |
| BARs | **no** | A BAR decides *where in physical address space the device answers*. A domain that could write one could park a device on top of memory it does not own, and no IOMMU stops that — translation governs what the device *reads*, not where it *responds*. |
| MSI-X table and PBA | **no** | RFC 0011's existing rule: an MSI is a memory write of an arbitrary vector to an arbitrary CPU. |

So the proposal is a **read-only** configuration-space capability plus a small mediated set, rather
than the page. That is less than "a domain owns its device" and more than today, and the reason it
is less is written in the table rather than left as an instinct.

### A virtqueue crate, shared the way a service crate is

The split-virtqueue protocol — descriptors, available, used, the fences between them — moves into a
crate that the kernel's driver and a domain's driver both compile. RFC 0013 already established the
shape: `services/vfs` is byte for byte the same code in the kernel and in `bin/vfsd`, and what
differs is a context of function pointers. A virtqueue's context is "how do I turn memory I hold
into an address the device understands", which is `DevAddr` in a domain and a physical address in
the kernel — one function, exactly as `Bulk::fill` was.

### The mock-MMIO harness

A test supplies a byte array and a table of "what this register returns when read". The driver runs
against it on the host. The first things worth testing are the ones that have already been wrong:
that a 64-bit register write lands as two 32-bit stores in the right order, that the available
index is published *after* the descriptor it refers to, and that a device reporting `0xffff` for a
vector is treated as a refusal rather than as vector 65535.

---

## Alternatives considered

**Leave it. Two drivers, two copies.** Defensible while there are two. The cost is paid per driver
and this design intends to have several — network, console, and whatever a real disk needs. The
three bugs were the invoice for the second one.

**A trait-based `Driver` abstraction, like `Service`.** Rejected for now. RFC 0013's trait works
because every service answers messages and differs only in which; drivers differ in almost
everything, and a trait wide enough for a block device and a network card would be a union of two
things rather than an abstraction of either. The framework proposed here is *primitives*, not a
shape drivers must fit.

**Generate register blocks from a device description language.** Rejected as premature: there is one
device family. `register_block!` is a macro over a table, and if a third device makes it repetitive
the macro is where the generator would attach.

**Give a domain its whole configuration space.** Rejected in the table above. BARs are the reason,
and it is a reason no amount of IOMMU fixes.

---

## Impact on existing design documents

- **`architecture.md`** — the driver section should say what a driver in a domain holds, which is
  now a real list rather than an aspiration.
- **`memory.md` §5** — ECAM adds a memory region the kernel maps and, for the first time, one it may
  hand out per function.
- **`security.md`** — the configuration-space table above is a new answer to "what may a driver
  domain reach", and belongs there rather than only here.
- **RFC 0013 step 6's note** that the bus must stay in the kernel is correct for port I/O and should
  be annotated with what ECAM changes.

---

## Security implications

**The good.** A driver in a domain holding a read-only configuration capability can identify its own
device without asking the kernel, which removes a syscall and grants nothing. `Mmio<T>` and
`register_block!` remove a class of silent wrong-width access. `Device::claim` makes "DMA-capable"
and "reset first" the same event.

**The risk this adds.** ECAM makes configuration space *mappable*, and a mistake in which fields are
delegable is a mistake that hands a domain a BAR. The mitigation is that the delegable set is a
table in code with a test per row, and that the default is read-only.

**The risk this does not address.** A driver in a domain is still trusted with its own device: it
can command that device to do anything the device can do, to the memory the device is allowed to
reach. RFC 0012 bounds the second half; nothing bounds the first, and nothing in this RFC changes
that.

---

## Performance implications

**Neutral by construction.** `Mmio<T>` and `register_block!` compile to the same volatile loads and
stores written by hand — the point is which ones are possible, not how fast they are.

**ECAM is faster than port I/O** for configuration access (a memory read against two port writes and
a read), which matters at enumeration and nowhere else.

**To be measured**: enumeration time before and after ECAM, and whether a virtqueue crate shared
between the kernel and a domain costs anything against the hand-written one. RFC 0013 step 5's
figures are the baseline: ~5,000 cycles a round trip for a domain placement.

---

## Testing plan

**On the host, which is the point:**

- Every register block: no two fields overlap, none leaves the block. A compile-fail test for each,
  because a runtime assertion about a layout is a test that ships.
- `Mmio<u64>` writes two 32-bit stores, low half first — asserted against a mock that records the
  width and order of every access. This is bug 1, and it is the test that would have caught it.
- The virtqueue: a descriptor chain is published only after the descriptors it names, and a used
  index that goes backwards is refused rather than believed.
- A device reporting `0xffff` for an MSI-X vector is a refusal.

**In QEMU:**

- The existing block driver gates, unchanged, against a driver rebuilt on the framework. **The
  criterion is that nothing changes**: same sectors, same `BHASKIX-`, same interrupt.
- ECAM enumeration finds the same devices port I/O finds, on the same machine, and says so — with
  the port-I/O path kept and compared, because "the new one found three devices" is not evidence
  that it found the right three.

---

## Unresolved questions

1. **How much of configuration space is delegable?** The table above is a proposal. The command
   register in particular is a judgement call: mediating it means a syscall per bus-master enable,
   and granting it means granting DMA without a window.
2. **Does the kernel keep its own driver?** If a virtqueue crate is shared and a domain driver
   works, the kernel's block driver is a second implementation of a solved problem — but it is also
   how the machine reads its root filesystem before any domain exists. Probably it stays and shrinks.
3. **Where does `register_block!` live?** A `device` crate below the kernel, or in `arch`? It is not
   architecture-specific, but MMIO ordering is.
4. **Legacy PCI on machines with no MCFG.** Keep the port-I/O path as a fallback, or refuse? A
   fallback that is never tested is a fallback that does not work.

---

## Implementation plan

1. **`Mmio<T>` and `register_block!`**, with the host tests above and no user. The macro's
   overlap assertions are the deliverable, not the accessor.
2. **The kernel's virtio driver moved onto them.** No behaviour change, and the existing gates are
   the criterion — the same shape as RFC 0013 step 1.
3. **The mock-MMIO harness**, and the virtqueue's first host tests. Written against the *existing*
   driver, so the tests are about the protocol and not about the framework.
4. **ECAM**: `MCFG`, a memory-mapped configuration accessor, and the comparison gate against the
   port-I/O path. The fallback question is answered here or the fallback is deleted.
5. **The virtqueue crate**, shared by the kernel's driver and `bin/blkd`. `bin/blkd` loses its
   hand-written copy, and the criterion is again that nothing changes.
6. **A configuration-space capability**, read-only, with the delegable table and a test per row.
   `bin/blkd` identifies its own device without asking the kernel.
