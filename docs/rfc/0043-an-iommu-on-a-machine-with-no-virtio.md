# RFC 0043: An IOMMU on a machine with no virtio

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-08-23, all five steps done 2026-08-24 — including a boot on the SR550 where translation came up for the first time on physical hardware — awaiting the project lead's acceptance.** Opened the day the first readable hardware boot showed that RFC 0012 has never run on real hardware. The unit's tables are separable from any device's window; **unresolved question 1 is ANSWERED: pass-through, chosen by the project lead 2026-08-24**, and steps 3–4 are built and gated. Steps 1–2 landed 2026-08-23; step 5 — the watched boot on the SR550 — is the one that remains. ~~unresolved question 1 — refuse, identity-map, or pass-through — is still the project lead's to answer, but it is no longer blocked on a document.** The Intel VT-d specification was read on 2026-08-24: the context-entry translation-type field is at **bits 3:2**, pass-through is **`10b`**, `ECAP.PT` is bit 6, and pass-through carries a second obligation the RFC had not known — `AW` must be set to the largest AGAW the hardware supports. Steps 2–5 wait on the decision, not on the layout |
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

### What step 2 found, which changes this argument

**The emulator has the same problem, and has had it all along.** Surveying the
bus on the `iommu` lane:

```
      dma unknown  00:01.0 1234:1111 class 03.00 -- no driver here, so no window
      dma unknown  00:1f.2 8086:2922 class 01.06 -- no driver here, so no window
      dma unknown  00:1f.3 8086:2930 class 0c.05 -- no driver here, so no window
    dma devices    10 functions: 5 drivable, 2 bridges, and 3 endpoint(s) this kernel cannot describe
```

A display adapter, a **SATA AHCI controller** and an SMBus. The middle one is a
real bus master. And on that lane **translation is enabled anyway** — it has been
since RFC 0012 — with those three holding no context entry at all.

Nothing faults, because nothing drives them and an idle device issues no
transactions. But the guarantee this project states as *"a DMA-capable device
reaches only what it was given"* has never held for them. It holds for the
devices with drivers. That is a smaller claim than the one `security.md` makes,
and it is true on the emulator as well as on hardware.

> **Superseded in part, 2026-08-24.** RFC 0046 step 2 gave `00:1f.2` a driver, a
> window and a domain of its own, so that lane now reads *"6 drivable, 2 bridges,
> and 2 endpoint(s) this kernel cannot describe"*. **Three became two**, and what
> remains is the display adapter and the SMBus. The survey above is kept as
> written because it is what was measured on the day, and because the argument
> below rests on it: two endpoints with no window is still not zero, so answer 1
> stays eliminated for exactly the reason it was.
>
> One further correction the same day: the predicate that produced the
> "drivable" count **ignored the programming interface** and answered *yes* for
> any USB controller, so a UHCI or EHCI controller would have been counted as
> containable and left out of this very number. No lane in this tree has one, so
> no count printed here has ever been wrong. Fixed in `iommu::survey`.

**This eliminates answer 1 below.** "Refuse to enable unless every endpoint has a
window" would turn the IOMMU **off on QEMU**, where three endpoints have none —
taking every existing IOMMU gate with it. A rule that disables the feature on the
only machine that currently exercises it is not a rule, it is a retreat.

**And it re-frames the question.** The choice for an endpoint with no driver is
not two options but three, and one of them is what the code already does:

| | What the device can reach | What happens if it does DMA |
|---|---|---|
| **Absent** (today) | nothing | refused — a fault, and on a boot device a dead machine |
| **Identity-mapped** | all of memory, at its own addresses | works; costs a page table over all of RAM |
| **Passed through** | all of memory | works; costs nothing, and `vtd.rs` already warns that choosing it by accident is "a device that reaches all of memory while the machine reports an IOMMU" |

Today's behaviour is *absent*, and it survives on QEMU only because the three
endpoints there are idle. On a real server the boot device is not idle.

### What "DMA-capable device this kernel can see" means

Enumerable from PCIe, and today that is: virtio block, virtio net, xHCI
controllers, and — since RFC 0046 step 2, 2026-08-24 — a SATA controller
presenting AHCI's registers. Anything else on the bus — a SAS controller, an NVMe drive, a
management NIC — is a bus master this kernel has no driver for and no window for.

**Two answers, and this RFC does not choose between them.** It is the unresolved
question below, because the choice is a security decision rather than an
engineering one:

1. ~~**Refuse to enable.**~~ **Eliminated by step 2**, above: it would turn the
   IOMMU off on QEMU, where three endpoints have no window, and take every
   existing IOMMU gate with it.
2. **Give every enumerable endpoint an identity-mapped window.** Translation is
   on, the units are programmed, and a device the kernel does not drive reaches
   what it always reached. That is *not containment* for those devices, and
   calling it so would be the kind of claim this project refuses — but it does
   contain the devices that do have drivers.
3. **Pass those endpoints through**, which the hardware supports directly and
   which costs no page table at all. Same guarantee as 2 and much cheaper — and
   `arch/x86_64/src/vtd.rs` already carries the warning that makes it dangerous:
   *"choosing it by accident is a device that reaches all of memory while the
   machine reports an IOMMU."* Chosen **deliberately**, and reported per device,
   it is not an accident. That distinction is the whole of the decision.

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

> ~~**This RFC does not weaken anything; it is about a guarantee that is
> currently absent.**~~ **Corrected 2026-08-24, when answer 3 was taken.** That
> sentence was written while the answer was still open and it is no longer
> true on the emulator. **On QEMU this is a loosening**: the display adapter at
> `00:01.0` and the SMBus at `00:1f.3` had no context entry, so their DMA was
> *refused*; they now reach all of memory. Nothing drives them and nothing has
> ever faulted, which is why it costs nothing today — but "refused" and
> "unrestricted" are different, and the document said otherwise.
>
> **On real hardware it is a strict improvement**, and that is the trade: those
> endpoints reached everything already, because translation could not be turned
> on at all. Enabling it contains the devices that *do* have drivers. Some
> containment, where there was none.

The danger is in answers 2 and 3 alike: giving a device the kernel does not
drive what it already had, where a reader who saw "iommu enabled" might believe
otherwise. **Whichever answer is taken, the boot report must name every device
that got a window and say which kind it got** — which is why the line reads
*"passed through deliberately -- it reaches all of memory, and is not
contained"*, names the device, and is gated on those words rather than on a
tally.

**A limit found by trying to break it.** Writing the *reserved* `TT` encoding
`11b` instead of pass-through's `10b` produced a **completely clean boot** —
QEMU's `intel-iommu` did not police it, and the two devices never issue DMA, so
nothing ever walked their context entry. The host test over the bit layout is
therefore the **only** thing standing between the right encoding and a wrong
one; no boot gate can see it. Stated because the reverse would be assumed.

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

1. **Identity-map, or pass through?** Refusing is eliminated (step 2). Both
   remaining answers give an undriven endpoint everything it already had; they
   differ in cost and in what the boot report must then say. A security
   decision, and the one this RFC exists to put in front of somebody.

   > **And neither is currently buildable, established 2026-08-23 rather than
   > assumed.** The question is not only which policy is right; it is which one
   > can be built from what can be verified here.
   >
   > **Identity-map** needs large pages, and this kernel's IOMMU tables have
   > none: `map_page` walks to level 1 and maps 4 KiB, and `vtd::PageEntry`
   > carries an address and rights with no size bit. The SR550 has 192 GiB, so
   > an identity map of it is 50,331,648 leaf entries — about **402 MB of page
   > tables per device**, before the levels above them. Not a tuning problem; a
   > missing feature.
   >
   > ~~**Pass-through** needs the context entry's translation-type field, and
   > **the field's position could not be established on this machine.**~~
   > **UNBLOCKED 2026-08-24.** The Intel VT-d Architecture Specification is a
   > public document; it was fetched and read, and it answers this directly.
   > **rev 5.20 §9.3, figure 9-3 "Context-Entry Format":**
   >
   > | bits | field |
   > |---|---|
   > | `0` | `P` Present |
   > | `1` | `FPD` Fault Processing Disable |
   > | **`3:2`** | **`TT` Translation Type** — `00b` second-stage, **`10b` pass-through**, `11b` reserved |
   > | `11:4` | Reserved, must be 0 |
   > | `63:12` | `SSPTPTR`, *"ignored by hardware when TT is 10b"* |
   > | `66:64` | `AW` Address Width |
   > | `87:72` | `DID` Domain Identifier |
   >
   > This agrees with Linux's `CONTEXT_TT_PASS_THROUGH = 2` — `10b` at bits 3:2
   > — and **`ECAP.PT` is bit 6**, which the header also said. Both are now
   > sourced from the vendor's document rather than from a GPL header, which
   > was worth doing for licence reasons as well as for correctness.
   >
   > **And the specification adds an obligation this RFC did not know about.**
   > Of `AW`: *"When the Translation-type (TT) field indicates pass-through
   > processing (10b), this field must be programmed to indicate the largest
   > AGAW value supported by hardware."* So pass-through is **two** fields, not
   > one. Writing `TT` alone and leaving `AW` at the tables' width would be a
   > context entry that looks right and is not — exactly the class of error
   > this RFC refused to risk by writing a field from recall.
   >
   > *Recommendation, offered rather than taken:* **pass-through**, and the
   > prerequisite is now met. It costs no page tables, and "this device is not
   > translated" is a more honest thing for a table dump to say than a mapping
   > that looks like containment and is not. **The choice remains the project
   > lead's** — reading the document settles what pass-through *costs to
   > write*, not whether this system should offer it.
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
2. ✅ **Done 2026-08-23.** Enumerate every function on the bus and report them,
   naming each endpoint with no driver rather than counting it. Reporting only —
   no behaviour change — and it is what turned question 1 from two answers into
   three and eliminated one of them.
3. ✅ **Done 2026-08-24.** The decision, in `pass_through_or_say_why`: given
   what the unit supports, either every undrivable endpoint is passed through or
   the boot says why it could not. The bit layout it produces is host-tested and
   watched red — and that host test turned out to be the *only* thing that can
   catch a wrong `TT`, since a reserved encoding boots clean.
4. ✅ **Done 2026-08-24.** Wired into `enable` rather than a caller, because
   "before translation is on" is a property of that function's ordering and a
   caller could get it wrong silently. The report names every passed-through
   device and says it is not contained; one boot gate on the `iommu` lane,
   watched red three ways — the walk removed (0 of 2), the walk stopping after
   one endpoint (**1 of 2**, which is why the gate asserts the count rather than
   "at least one"), and the reserved `TT` encoding, which the boot could *not*
   catch.

   It also found a real check doing its job: `verify_window` asserts that the
   number of present context entries equals the number of devices attached, and
   the first wiring made three windows fail to read back — the pass-through
   entries looked exactly like the strays that check exists to catch. It now
   counts them explicitly rather than being loosened.
4b. ✅ **Done 2026-08-24, and it is why step 5 was not attempted on the first
   try.** Two things stood between this and a machine that is not QEMU, both
   found by reading rather than by booting:

   **Bring-up was gated on virtio.** `iommu_bringup` began `virtio::probe()?`,
   so on a server with no virtio device it returned before touching a register
   — which is the whole reason the SR550 has four working units and none
   programmed. `security.md` had recorded it as a sentence that described a
   defect and read like an explanation. The first device is now whatever this
   kernel can drive: virtio where there is one, so every lane keeps the machine
   it had, otherwise the AHCI controller. Verified by forcing the fallback on
   QEMU, where the machine came up around `00:1f.2` instead.

   **One context table was shared by every bus.** A context entry is selected by
   `(device << 3) | function` — unique within a bus and *not* across them; the
   bus is selected one level up by the root entry. This kernel allocated one
   context table and pointed every bus's root entry at it, which was invisible
   because every device on every machine it had run on was on bus 0. The SR550
   has 115 functions across `00`, `b1`, `ae` and more, and step 4 gives an entry
   to every endpoint it cannot drive — so **the first multi-bus machine would
   have been the first collision**, and one that replaced a *translating* entry
   with a pass-through one would have silently un-contained a device with
   nothing to report it. Context tables are now allocated per bus, lazily, as
   the specification describes. Verified by adding a `pcie-root-port` to the
   QEMU machine and watching a device on **bus 1** get its own entry.
5. ✅ **DONE 2026-08-24. Translation is enabled on the SR550, and this is the
   first time an IOMMU has been programmed on physical hardware in this
   project's history.**

   ```
   iommu window   00:11.5 48-bit, 4 levels, 0 reserved pages mapped, 2 refused
   iommu window   00:14.0 translating too, the xhci controller's own page table and domain, 2 in use
   iommu irq      remapping interrupts; compatibility format blocked
   dma            translating: this device reaches only what it was given
   ahci           00:11.5 8086:a1d2, translated
   ```

   **105 endpoints passed through across seven buses** — `00`, `02`, `07`,
   `5a`, `ad`, `ae`, `b1` — two devices contained, interrupt remapping on,
   16 CPUs, boot to completion. Captured over serial-over-LAN, so it is a boot
   somebody *read* rather than one somebody saw.

   **Three defects had to be fixed between step 4 and this working**, and each
   was invisible to every emulator boot:

   1. **The tables were built to a width the unit does not support.**
      `AddressWidth::fitting` chose from the `DMAR`'s host address width — 46
      bits here, so 39 — and these units do not offer 39-bit at all. The
      specification is explicit that the field must match `SAGAW`, and the
      tables are now built from it: **48-bit, 4 levels**. QEMU's unit reports
      `SAGAW` `0b00010`, 39-bit only, which is what the old code also chose —
      so no emulator boot could ever have found this.
   2. **The pass-through count was machine-wide and the check is per bus.**
      `verify_window` counts the present entries in *one* bus's context table;
      the expected total included pass-through entries living in six others, so
      the xHCI's window failed to read back. One counter per bus.
   3. **Bring-up returned silently** when there was no first device, which is
      what made the first hardware boot unreadable.

   `iommu=off` was ready and not needed.
