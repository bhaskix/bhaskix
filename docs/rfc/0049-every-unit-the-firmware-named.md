# RFC 0049: every unit the firmware named

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-25 — all five steps built and measured on hardware.** The SR550 programs **all four** units, and the xHCI's No-Op — unanswered on four consecutive boots — is answered: *"1 event (1 completion), success, dequeue advanced"*. **Accepted with five limits written here rather than left to be inferred.** *(1)* Every unit is given the **same root table**; device scopes are **not** parsed, so this does not support a machine whose units must walk different tables — deliberate, and §*What this does not do* says why. *(2)* **Interrupt remapping is still enabled on the first unit only**, which is narrower than `enable_interrupt_remapping`'s name suggests and is untested on a multi-unit machine. *(3)* It was measured on **exactly one** multi-unit machine, and **no emulator here can cover the multi-unit case at all** — QEMU describes one unit, so both new gates pin the single-unit path and the path this RFC exists for has one witness. *(4)* It does **not** fix the xHCI's port 1, which still answers nothing; that is separate and probably the BMC's. *(5)* The DMA refusal it made visible — `00:14.0` refused a read of `0xaa95f000` — is **explained but not proven**: the account is a controller firmware left running, doing DMA to firmware's own structures in the window between being caged and being reset, and nothing has demonstrated it |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0012](0012-iommu.md) (the IOMMU, and the rule this breaks), [RFC 0043](0043-a-window-for-every-device.md) (pass-through, and the survey this reuses), [RFC 0041](0041-usb.md) (the driver that found it) |

---

## Summary

This kernel programs **one** DMA remapping unit — `dmar.units().next()`, the
first structure in the firmware's table — and treats it as the IOMMU. A
platform may describe several, each governing a different set of devices, with
one of them carrying `INCLUDE_PCI_ALL` for everything the others do not claim.
On such a machine every device outside unit 0's scope is **not translated at
all**, while the boot report says it is. This RFC programs every unit the
firmware named.

## Motivation

An SR550 was booted on 2026-08-25 with the xHCI controller's DMA going
unanswered. The instruments added in `4df5ccd` reported this:

```
iommu unit 0   registers at 0xe3ffc000, claims only the devices its scope names  <- the one this kernel programs
iommu unit 1   registers at 0xedffc000, claims only the devices its scope names  (NOT PROGRAMMED)
iommu unit 2   registers at 0xf7ffc000, claims only the devices its scope names  (NOT PROGRAMMED)
iommu unit 3   registers at 0xd9ffc000, claims every device not claimed by another  (NOT PROGRAMMED)
```

Unit 3 is the one with `INCLUDE_PCI_ALL`, and on this platform it governs the
PCH — including the xHCI at `00:14.0`. What followed is a complete account of
the failure:

- The kernel built a window for `00:14.0` and wrote a context entry for it into
  **unit 0's** tables, where no hardware looks for that device.
- Unit 3, which does govern it, was never enabled, so the device is untranslated.
- The controller used the address it was handed — `0x100001000` — as a
  **physical** address, read whatever the machine keeps there, and found no
  command.
- No fault was recorded, because no unit was in a position to raise one.
- The controller reported itself running, its command ring running, and no
  error of its own. Every symptom follows.

**This is not primarily a driver bug, and its cost is not primarily a broken
controller.** RFC 0012's position is that a device covered by no unit is to be
treated as if there were no IOMMU at all. On a multi-unit machine this kernel
covers most devices with no unit and reports them as translated. The
containment claim in `security.md` is, on that class of machine, false.

Every emulator this kernel has run on describes exactly **one** unit, where
taking the first is correct by accident. This is the fourth thing this month
that was correct only on an emulator.

## Design

### What a unit governs

A `DRHD` structure names a register window, a segment, and a device scope. A
device is governed by the unit whose scope names it; a device named by no
scope is governed by the unit for its segment carrying `INCLUDE_PCI_ALL`, if
there is one. The parser in `bhaskix_arch::acpi` already records
`register_base`, `segment` and `covers_all` for every unit — the information
has been there and was discarded one line into the kernel.

### One root table, every unit

Each unit is programmed with the **same** root table. Nothing in the
specification requires a unit to have its own, and sharing one makes the
question "which unit governs this device" stop mattering for correctness: a
device's context entry is found by whichever unit handles its request, because
every unit walks the same tables.

This is deliberately *not* the same as computing scope membership and
programming each unit with only its own devices. That would be more precise,
more code, and would put a parser for device-scope structures on the path to a
machine booting — and getting it wrong means a device silently untranslated,
which is the failure being fixed. Sharing is correct without needing to be
clever; scope parsing can come later if a machine ever needs it.

**Domain ids** stay as they are. They are per-unit namespaces, and using the
same numbers in each unit for the same device is consistent, not a collision.

### Refusal is per unit, and says so

`enable` today refuses the whole IOMMU when one unit will not take the width
the tables were built to. With several units, a unit that refuses means *its*
devices are untranslated while others are contained. Both facts get reported,
per unit, and the summary line says how many of how many were programmed. A
kernel that programmed three of four units and said "translating" would be
repeating the error this RFC exists to fix.

The width the tables are built to must be supported by **every** unit that is
programmed, since they share the tables. The narrowest common width wins, and
the report says which unit set it.

### Faults and invalidation follow

`report_faults` reads the unit this kernel programs. It becomes every
programmed unit, naming which one recorded each fault — a fault on unit 3 and a
fault on unit 0 are different devices and different tables.

`invalidate_contexts`, called after each lazily-written context entry, must
reach every programmed unit for the same reason.

## Steps

1. `Report` carries every unit; the boot report lists them. **Done** in `4df5ccd`.
2. `enable` programs every unit with the shared root table, refusing per unit
   and reporting per unit.
3. Width negotiation across units: the tables are built to the narrowest width
   every unit supports, and the report names the constraint.
4. `report_faults` and `invalidate_contexts` cover every programmed unit.
5. Boot on the SR550 and read whether the xHCI's no-op is answered. That is the
   measurement this RFC exists to produce, and it is the one an emulator cannot
   give: QEMU has one unit. **Done, 2026-08-25:**

```
iommu          all 4 units programmed
xhci rings     answered the no-op at 0x100001000: 1 event (1 completion, 0 port,
               0 transfer, 0 unknown), success, dequeue advanced
```

   The completion named the address the command was written to, so the
   controller read the command ring and wrote the event ring, and both are the
   same conversation this kernel is having.

   **And the fault instrument earned its place on the same boot:**

```
iommu fault    unit 3: 00:14.0 was refused a read of 0xaa95f000: it asked to read
               where it has no read permission -- not mapped (reason 0x6)
```

   That is containment working — a device reaching for memory nobody granted
   it, refused and named.

   **A correction, recorded rather than edited away.** This paragraph first
   said `0xaa95f000` *"sits just below the firmware-reserved region at
   `0xaabf8000`"* and implied the controller was reaching for the reserved
   region this kernel refuses to identity-map. **That was an inference, it was
   not checked, and it is wrong.** The address is in neither region: 2.60 MiB
   below the start of `0xaabf8000..=0xaac09fff`, and 52.01 MiB above the end of
   `0x9f554000..=0xa755bfff`. Two point six megabytes is not "just below", and
   the reserved-region story was a tidy explanation arrived at by looking at
   the first nearby number rather than by subtracting.

   What is actually known is smaller and stranger: **the controller read an
   address nobody gave it.** It is not an address from its window — those are
   at `0x100000000` and above — and it is not a reserved region.

   **Two more instruments settled it, and the second refuted the first
   guess.** The driver now records the physical extent of every frame it
   allocates, and faults are read twice: once before any driver here has
   touched a device, and once after bring-up. Reading clears the records, so
   the two reports are disjoint by construction.

```
xhci frames    physical 0x303f8c0000..=0x303f8e9fff
iommu faults   [before drivers] none recorded by any programmed unit
iommu fault    [during bring-up] unit 3: 00:14.0 was refused a read of 0xaa95f000
```

   The frames are at **194 GiB**; the refused address is at **2.66 GiB**. So it
   is not a device address confused with a physical one either — that was
   guess two, and the extent line kills it.

   And the fault is **not** left over from firmware's own use, which was guess
   three: nothing faulted before this kernel touched anything.

   **What the evidence supports.** The IOMMU window for `00:14.0` is built in
   `iommu_bringup`, well before `xhci::init` runs. From that moment the
   controller is translated, and its page table contains this driver's frames
   and nothing else. But firmware left the controller **running**, with
   `DCBAAP`, `CRCR` and `ERSTBA` pointing at firmware's own structures in low
   memory — and `take_ownership` takes the semaphore without stopping it.
   `bring_up` halts it a moment later. In that window a controller nobody has
   reset yet does DMA to firmware's addresses, and the IOMMU refuses it.

   `0xaa95f000` is in low memory where firmware's structures live, the fault is
   a **read**, and it appears only in the window between caging the controller
   and resetting it. **This is containment working**, on a bus master that
   firmware left running, and it is benign: the controller is reset moments
   later and then answers its first command.

   It is left in place rather than suppressed. The available fix — halting the
   controller the instant ownership is taken, rather than at the start of
   `bring_up` — is a change to bring-up ordering, and it belongs to whoever
   next has the machine and can measure it. A fault line that is explained is
   worth more than a boot report with nothing in it.

   Still open on that machine, and not claimed by this RFC: `xhci device not
   addressed: no port has a device on it`. The controller works; nothing has
   yet been found on a port.

## What this does not do

**It does not parse device scopes.** A device named by a specific unit's scope
and a device covered by `INCLUDE_PCI_ALL` are treated identically, because
every unit shares the tables. If a machine ever appears where that is not
enough — a unit whose tables must differ — it needs its own RFC and its own
measurement.

**It does not claim the xHCI will work.** Translating the controller correctly
removes the explanation the evidence currently supports. If the no-op is still
unanswered afterwards, that is a second bug and this RFC has still fixed a real
one.

## Security

This **widens** containment rather than narrowing it, which is the unusual
direction for a change to this subsystem and worth stating plainly: devices
that were reaching all of physical memory while being reported as contained
will be contained. `security.md`'s IOMMU row currently overstates what holds on
a multi-unit machine and must be corrected in the same change as step 2 —
not after it.

The correction is owed regardless of whether the rest is built.

## Testing

- Host tests for width negotiation across a set of units, each watched red.
- `make test-boot-iommu` unchanged: QEMU has one unit, so every existing gate
  must produce exactly what it produces today. Unchanged behaviour proven
  unchanged, which RFC 0043 asks for.
- A gate on the single-unit lane asserting the report says one of one programmed.
- The SR550, which is the only machine that can exercise any of this.
