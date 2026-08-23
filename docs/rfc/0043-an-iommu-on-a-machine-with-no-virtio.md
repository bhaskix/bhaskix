# RFC 0043: An IOMMU on a machine with no virtio

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-23, step 1 implemented.** Opened the day the first readable hardware boot showed that RFC 0012 has never run on real hardware. The unit's tables are separable from any device's window; **unresolved question 1 — refuse, or identity-map — is still unanswered, and steps 2–5 wait on it** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/iommu`, `kernel/lib.rs` bring-up |
| **Milestone** | Phase 2. It does not add a feature; it makes an existing one true off the emulator |
| **Depends on** | [RFC 0012](0012-iommu.md) (the IOMMU, and the sequence this changes), [RFC 0041](0041-a-usb-keyboard.md) (rule 1, and the circularity below), [RFC 0042](0042-reading-the-boot-report-back.md) (which is how this was found at all) |

---

## Summary

**The IOMMU has never been enabled on a real machine.** Its bring-up is sequenced
after finding a virtio block device, and no real server has one. This RFC
separates *turning translation on* from *containing a particular device* — and
argues that doing so safely is a harder claim than the current code makes, because
enabling translation on a machine whose boot device has no window stops the
machine.

## Motivation

### What the first readable hardware boot said

```
    iommu          4 units found, not enabled; 46-bit addresses, 2 reserved regions, interrupt remapping supported
    virtio-blk     no block device on the bus
    xhci           00:14.0 8086:a1af REFUSED: no iommu translation, and a bus master without one can read and write all of memory
```

Four units, described and idle. The cause is two lines of `iommu_bringup`:

```rust
let found = found.filter(|report| report.units > 0)?;
let device = virtio::probe()?;          // None on a real server
```

Everything after that — building the tables, mapping the firmware's reserved
regions, `enable`, interrupt remapping, and the windows for every other device —
is downstream of a `?` that returns on any machine without virtio.

### Why nothing caught it

Every gate in this project runs on QEMU, and QEMU always has the device the probe
is looking for. The check that would have failed is *"does the IOMMU come up on a
machine with no virtio device"*, and until 2026-08-23 there was no such machine
whose boot report anybody could read.

### What it costs

[RFC 0012](0012-iommu.md) is the argument that a DMA-capable device reaches only
what it was given. [security.md](../security.md) §1 marks **T3** and **T4**
mitigated by it. On the one piece of real hardware this system has run on, that
mitigation **is not in effect** — and `security.md`'s row now says so.

### The circularity, which is the interesting part

On the SR550 the only DMA-capable device this kernel recognises is the **xHCI
controller**. RFC 0041's rule 1 refuses to drive a controller that is not behind a
translation. So:

- the controller is not driven, because there is no translation;
- there is no translation, because bring-up wanted a device to anchor it;
- the only device it could have anchored on is the controller.

The rule fired correctly and the machine got no USB. Neither half is wrong on its
own. **The sequence is.**

## Design

### The root table belongs to the machine, not to a device

`build_window(report, device, domain, hhdm)` does two things at once: it
allocates the root, context and page tables, and it writes a context entry for
one device. The first is about the *unit*; the second is about a *device*. They
are separated:

- `iommu::build_tables(report, hhdm) -> Option<Tables>` — root and context
  tables, allocated and zeroed, no device named. Every context entry absent,
  which means *every device is refused* until one is given a window.
- `iommu::attach_to(&tables, device, domain, hhdm)` — the one place a context
  entry is written, and the only way a device gets a window.

`build_window` then becomes `build_tables` followed by one `attach_to`, and
nothing else changes about what a window is.

> **Corrected 2026-08-23 by building it.** This paragraph named the new function
> `attach_device`, which already existed with a different signature — it takes an
> installed `&Window` and reuses its tables. Rather than change what every
> existing caller passes, `attach_to` is the new one and `attach_device` became a
> single call to it. The duplicated entry-writing code the two of them used to
> share went with the change.

### But enabling with nothing attached would stop the machine

**This is the part that makes this an RFC and not a patch.** With translation on
and a context entry absent, that device's DMA is refused. On a real server the
boot device is on the PCIe bus — and on the machine this was found on, the boot
device is a **CD emulated by the BMC over the same bus**. Enable translation with
no window for it and the machine stops reading the medium it is running from.

QEMU has never shown this because the one device that mattered there was the one
the sequence was anchored on.

So the rule this RFC proposes is not "enable whenever there is a unit". It is:

> **Translation is enabled only when every DMA-capable device this kernel can
> see has a window.** A device the kernel cannot describe is a device it must not
> silently refuse, so a machine holding one boots with the IOMMU off — loudly,
> in the words `iommu=off` already uses.

That is a weaker guarantee than "the IOMMU is always on", and it is the honest
one. It also makes the boot report's job clear: it must say *which* devices got
windows and which device, if any, stopped translation from coming up.

### What "DMA-capable device this kernel can see" means

Enumerable from PCIe, and today that is: virtio block, virtio net, and xHCI
controllers. Anything else on the bus — a SAS controller, an NVMe drive, a
management NIC — is a bus master this kernel has no driver for and no window for.

**Two answers, and this RFC does not choose between them.** It is the unresolved
question below, because the choice is a security decision rather than an
engineering one:

1. **Refuse to enable.** Nothing is contained, and the report says which device
   prevented it. Safe for the machine, and the guarantee is off exactly when a
   machine has hardware this kernel does not understand — which is most of them.
2. **Give every enumerable function an identity-mapped window.** Translation is
   on, the units are programmed, and a device the kernel does not drive reaches
   what it always reached. That is *not containment* for those devices, and
   calling it so would be the kind of claim this project refuses — but it does
   contain the devices that do have drivers, and it is what a real system does
   during bring-up before it knows better.

### The reserved regions become load-bearing

The SR550 declares **2 reserved regions**. QEMU declares none, and `iommu.rs`
already says the refusal path therefore has no natural test in the emulator.
Those regions are firmware telling the kernel *this device must keep reaching
this memory* — typically USB legacy emulation, which is how a BMC's virtual
keyboard works. `map_reserved` exists and is called; it has never run against a
machine that declared any.

## Alternatives considered

**Pick a different anchor device.** Fifteen lines: try virtio block, then virtio
net, then xHCI. It would have made the SR550 work and it is the wrong shape — the
root table is not any device's, and the next machine with a different first
device would find the same bug wearing a different hat.

**Enable the IOMMU only when asked.** An `iommu=on` flag. Honest, and it means
the containment the architecture argues for is off by default on every real
machine, which is worse than the bug.

**Leave it.** The gap is now written down in `security.md`, so nothing is being
claimed falsely. But T3 and T4 are the rows the whole IOMMU exists for.

## Impact on existing design documents

- [RFC 0012](0012-iommu.md) — its sequence is *build, identity-map, then enable*,
  and that is unchanged. What changes is what "build" is anchored on.
- [security.md](../security.md) §1 — the IOMMU row already carries the correction
  made on 2026-08-23. If answer 2 above is chosen, it needs a second sentence
  about what an identity-mapped window is and is not.
- [RFC 0041](0041-a-usb-keyboard.md) — rule 1 stops being unreachable on real
  hardware. The USB keyboard this project built cannot run on the machine it was
  built for until this lands.

## Security implications

**This RFC does not weaken anything; it is about a guarantee that is currently
absent.** The danger is in answer 2: identity-mapping a device the kernel does not
drive gives it what it already had, and a reader who saw "iommu enabled" might
believe otherwise. Whichever answer is taken, the boot report must name every
device that got a window and say which kind it got.

## Performance implications

None worth measuring. Bring-up cost, once, and the report already prices it.

## Testing plan

**Host-testable:** the anchor decision and the "may we enable" predicate are pure
functions over a list of enumerated devices. Which devices got windows, which did
not, and whether that permits enabling — all decidable without a machine, and all
watched red.

**QEMU:** unchanged behaviour must be proven unchanged. The `iommu` lane has a
virtio block device and must still come up exactly as it does today, with the
same windows and the same domain ids.

**And a machine with no virtio device is now testable**, which it was not before
2026-08-23: the SR550 boots with four units and no block device, and the gate is
that it says what it did about each of them. Whether translation may safely be
*enabled* there is the unresolved question, and the first boot that tries it
should be one somebody is watching.

## Unresolved questions

1. **Refuse, or identity-map?** §"What DMA-capable device means". A security
   decision, and the one this RFC exists to put in front of somebody.
2. **What about functions behind a bridge?** Requester ids are rewritten by
   PCIe-to-PCI bridges, and a context entry keyed on the wrong id contains
   nothing. No machine here has one yet.
3. **Should `iommu=off` remain the only escape hatch**, or does this need an
   `iommu=permissive` that enables the units and identity-maps everything, so a
   machine that will not boot with containment can still be diagnosed with the
   unit programmed?
4. **Does the BMC's emulated CD survive translation?** The machine boots from it.
   Nothing here knows whether its requester id is one the firmware declares a
   reserved region for, and the first attempt will find out the hard way.

## Implementation plan

1. ✅ **Done 2026-08-23.** Split into `build_tables` (the unit's half, no device
   named) and `attach_to` (the one place a context entry is written).
   `build_window` is now the two in sequence and `attach_device` is `attach_to`
   over an installed window's tables — so the duplicated entry-writing code is
   gone with them.

   *Byte-for-byte, measured.* The boot report does not print table addresses, so
   a temporary probe did, on the `iommu` lane, before and after:
   `root 0xec36000 ctx 0xec37000 pt 0xec38000 width 39 domain 0` — identical,
   because the allocation order is unchanged. The probe was removed; the change
   is one file.
2. Enumerate every DMA-capable function the kernel can see, and report them.
3. The predicate: may translation be enabled? Pure, host-tested, watched red.
4. Wire the decision, with the report naming every device and its window.
5. A boot on the SR550, watched, with `iommu=off` ready.
