# RFC 0046: A driver for hardware that exists — AHCI

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-24 — all six steps, in one day.** Bhaskix identifies, reads and writes a SATA disk from ring 3, behind an IOMMU window and domain of its own, and serves the same `block::READ`/`WRITE` interface `bin/blkd` serves. **Step 1**: the `ahci` crate — command lists, command tables, the H2D FIS, physical region descriptors and the `IDENTIFY` parser, `forbid(unsafe_code)`, eight properties watched red and 60,025,250 fuzz executions over the parser. **Step 2**: discovery and refusal — the controller found by class/subclass/**programming interface**, quiesced, given a window, and refused by name without one; RFC 0043's uncontained endpoints on the `iommu` lane went **3 → 2**, and `security.md` says so. **Step 3a**: the bring-up sequence, thirteen properties watched red against a device model that *refuses* rather than a register file that agrees. **Step 3b**: `bin/ahcid` in a domain — and the recalled register offsets met a real controller and held. **Step 4**: `IDENTIFY DEVICE`, and the first device this driver ever met was **not a disk** — QEMU's `q35` puts the boot CD on this controller, and ATAPI aborts that command by specification, so `PxSIG` is read before anything is asked. **Step 5**: sector zero, matched by its **bytes** and not a byte count. **Step 6**: a sector written and read back byte-for-byte on a sector that is not sector zero, and the block service a filesystem can mount on — whose self-test is `block_service_self_test` with one endpoint and one string changed, which is the whole argument of this document made checkable. **What acceptance does not claim, stated here rather than left to be inferred: ~~the register offsets have never been read from a specification~~ — DISCHARGED 2026-08-24** by fetching and reading the Serial ATA AHCI 1.3.1 Specification. **Every value it covers was correct**: twenty offsets, the port address formula (§3, *"Port offset = 100h + (PI Asserted Bit Position * 80h)"*) and thirteen bit positions, no discrepancy — the recall was right, and it is now sourced rather than merely agreed with by a machine. A narrower caveat replaces it: AHCI §3.3.9 defines `PxSIG` as a *layout* only and says nothing about which values mean which device, so the two signature constants remain recall, belonging to the Serial ATA / ATA command set; **nothing has run on the SR550's `00:11.5`**, because translation is off there pending RFC 0043, and that refusal is RFC 0012's rule working rather than a gap; and **no filesystem has been mounted on this driver** — the interface is served and answered, which is a smaller claim than `bin/fsd` running on it |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | a new `ahci` crate, a new `bin/ahcid` domain, `kernel/iommu` (one more window) |
| **Milestone** | Phase 2. It is the first driver in this tree for a device that is not an emulator's invention |
| **Depends on** | [RFC 0014](0014-driver-framework.md) (the driver framework and the `device` crate), [RFC 0012](0012-iommu.md) (a bus master is contained or refused), [RFC 0015](0015-filesystem.md) (the block service interface it serves), [RFC 0043](0043-an-iommu-on-a-machine-with-no-virtio.md) (whose uncontained-endpoint problem this partly closes) |

---

## Summary

Every storage device this system can drive is **virtio** — a device that exists
because an emulator invents it. This proposes `bin/ahcid`: a driver for the SATA
AHCI controller, serving the same `block::READ`/`block::WRITE` interface
`bin/blkd` already serves, so `bin/fsd` cannot tell which is underneath.

The hardware is not hypothetical in either direction. QEMU's `q35` has an AHCI
controller at `00:1f.2` and always has; the Lenovo SR550 this project tests on
has one at `00:11.5`. Neither has ever had a driver here.

## Motivation

**1. The only storage this system can drive is an emulator's.** `bin/blkd` is
virtio-blk. That is the right first driver and the wrong only one: it means
every storage claim this project makes rests on a device that does not exist
outside a hypervisor. The filesystem, the journal, the page cache and the
package manager have all been exercised against exactly one backing device, and
its failure modes are the ones a cooperative emulator produces.

**2. The Linux personality's file work has never run on hardware.** RFC 0005's
Tier 1 — directories, `getdents64`, `fstat` — is gated on every QEMU lane and
skips on the SR550, because that machine has no virtio disk. The skip is honest
and it is also a ceiling: nothing in Tier 1 can be tested on real hardware until
something can read a real disk.

**3. It closes one of RFC 0043's own holes.** That RFC records QEMU's AHCI
controller as one of three endpoints with no driver, therefore no window,
therefore **no containment** — while translation is enabled around them:

> *"A display adapter, a SATA AHCI controller and an SMBus. The middle one is a
> real bus master. […] the guarantee this project states as 'a DMA-capable
> device reaches only what it was given' has never held for them."*

A driver gives that controller a window. One of the three uncontained bus
masters on the lane that exercises the IOMMU stops being uncontained, and the
gap between `security.md`'s claim and what holds gets measurably smaller.

## Design

### Where it runs

A domain, like every other driver here — `bin/ahcid`, holding a `DmaWindow`
capability for its own device, an MMIO capability for the controller's
registers, and the endpoint it serves. RFC 0014's framework already does this
for `bin/blkd`; nothing new is asked of the kernel except one more window.

**It serves the existing interface and adds nothing to the ABI.**
`block::READ` and `block::WRITE` are what `bin/fsd` calls, and a second
implementation of them is the whole point: a filesystem that had to know which
driver was underneath would be a filesystem with a driver inside it.

### What AHCI actually requires

Four structures in memory the device reaches, and this is where the work is:

- **The command list** — 32 slots per port, 32 bytes each, at a 1 KiB-aligned
  address the port's `CLB`/`CLBU` registers name.
- **The received-FIS area**, 256 bytes, 256-aligned, named by `FB`/`FBU`.
- **A command table** per issued command: a 64-byte command FIS, then a
  scatter-gather list of physical region descriptors.
- **The FIS itself** — a Register Host-to-Device FIS carrying the ATA command,
  the LBA split across six bytes in two groups, and a sector count.

Every one of those is a **byte layout**, which is the same shape of problem as
RFC 0038's xHCI work and gets the same treatment: the arithmetic goes in an
`ahci` crate with `#![forbid(unsafe_code)]`, host tests over the raw dwords, and
nothing about it needs a machine to test.

### The sequence, and the parts that are load-bearing

1. **Find the controller** — PCI class `01`, subclass `06`, prog-if `01` (AHCI).
   Subclass alone is not enough: `00:17.0` on the SR550 is class `01.04`, the
   same silicon in RAID mode, and it does not speak AHCI.
2. **Take ownership from the firmware** if `CAP2.BOH` says the BIOS has it —
   the BIOS/OS handoff. Skipping it on a machine that wants it means the
   firmware and this driver both think they own the controller.
3. **Enable AHCI mode** (`GHC.AE`), then reset (`GHC.HR`) and wait for it to
   clear — bounded by a deadline and refused if it does not, never spun on.
4. **Per port**: stop it (`CMD.ST`, `CMD.FRE` clear, wait for `CR`/`FR`), set
   `CLB`/`FB`, start it, and read `SSTS.DET` to see whether anything is
   attached — this is the register that answers *"is there a disk on this
   port"*, which the survey could not.
5. **`IDENTIFY DEVICE`**, which gives the sector count and the logical sector
   size, so the block service's answers come from the device rather than from a
   constant.
6. **`READ DMA EXT`**, and later `WRITE DMA EXT`.

**Polling before interrupts.** The port's `IS` register says when a command
completed, and a first driver that polls it is a driver whose failure is a
timeout rather than a lost wakeup. Interrupts are RFC 0014's delegated-IRQ
mechanism and are a later step, with the polled version kept as the thing the
interrupt path is measured against.

### Failure behaviour

- **No controller** — the domain reports it and exits; a machine without one is
  not a broken machine, and `bin/blkd` already sets that precedent.
- **No IOMMU window** — refused, loudly. RFC 0012's rule is that a bus master is
  contained or it does not run, and a storage driver is the last place to make
  an exception. **On the SR550 this means the driver will refuse today**, because
  translation is off there pending RFC 0043 — see below.
- **A port with nothing attached** — skipped, and said, because "no disk" and
  "a disk that will not answer" are different and a driver that conflates them
  sends the next reader to the wrong place.
- **A command that never completes** — a deadline, and a refusal naming the port
  and the register that did not settle.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Extend `bin/blkd` to speak both | One domain holding two devices' windows, and a virtio driver's failure taking AHCI with it. The service framework's whole shape is one driver, one domain | Never for two buses this different |
| Wait for RFC 0043 so it can run on the SR550 | The driver is testable in QEMU today and closes one of RFC 0043's own uncontained endpoints there. Waiting inverts the dependency | — |
| Drive the SR550's MegaRAID instead | That is where the machine's real disks are, and it is a vendor-specific interface with no public register-level guarantee. AHCI is documented and stable | The MegaRAID turns out to be the only path to a disk on that machine *and* documentation exists |
| Interrupts from the start | A lost wakeup and a hung command look identical, and there would be no polled path to compare against | After the polled path works and is measured |
| ATA PIO rather than DMA | No window needed, so no containment question — and no DMA means no bus mastering, which is precisely the property that makes this driver worth having as an IOMMU subject | Never; the containment is half the point |

## Impact on existing design documents

- **`docs/driver-model.md`** lists "AHCI/SATA" at item 11 of its future list.
  That line comes off it.
- **[RFC 0043](0043-an-iommu-on-a-machine-with-no-virtio.md)** counts three
  uncontained endpoints on the QEMU lane. It becomes two, and the RFC's own
  arithmetic changes.
- **`security.md`**'s claim that a DMA-capable device reaches only what it was
  given gets closer to true on the lane that tests it.
- **[RFC 0015](0015-filesystem.md)** gains a second backing device and needs no
  change, which is the evidence that its interface was drawn in the right place.

## Security implications

- **New authority?** One more `DmaWindow`, held by one more driver domain, for
  one device. No new kernel mechanism and no new method.
- **Reachable without a capability?** No.
- **A parser for untrusted input?** **Yes, and it is easy to miss.**
  `IDENTIFY DEVICE` returns 512 bytes *from the device*, and a sector count read
  out of it sizes later requests. A disk is not a trusted peer: firmware is
  buggy and a device can be hostile. The fuzz target is the identify parser, and
  the bound is that no field taken from it may size an allocation or an
  unchecked loop.
- **Does it move anything into scope?** It moves the QEMU AHCI controller from
  "uncontained bus master" to "contained", which is the direction that matters.

## Performance implications

Nothing is claimed. The number worth taking, once it reads, is a sector read
against `bin/blkd`'s on the same lane — not because AHCI should win, but because
two drivers serving one interface make each other measurable for the first time.
**A figure from QEMU is a figure about QEMU**, as 2026-08-24 demonstrated when
real hardware came in five times cheaper than TCG on a shootdown-dominated path.

## Testing plan

**Host**, and this is most of it: the command-list entry, the command table, the
H2D register FIS, and the physical region descriptors are byte layouts, tested
against raw dwords rather than round trips — a round trip through this project's
own writer and reader agrees with itself about a field at the wrong offset. The
`IDENTIFY` parser likewise, plus its fuzz target.

**QEMU**: a gate that reads sector zero of the disk `q35`'s AHCI controller
already has and finds the bytes `mkfs` wrote there — the same shape as the
existing block-service gate, and for the same reason: a driver that returned
zeroes would pass anything weaker.

**Hardware**: the SR550's `00:11.5`, once RFC 0043 lets translation come up.
Until then the driver refuses there, and **that refusal is the correct
behaviour, not a gap** — it is RFC 0012's rule doing its job on a real machine.

## Unresolved questions

1. ~~**Is a disk attached to `00:11.5`?**~~ **Still open on the SR550, and the
   instrument that answers it exists.** `SSTS.DET` is read per port and reported
   per port, so the question is now one boot away — but that boot cannot happen
   until RFC 0043 turns translation on, because the driver refuses an
   uncontained controller and that refusal is the rule working.

   **It was answered on QEMU, and the answer was a surprise worth keeping.**
   `q35` has a device on port 2 and it is **the boot CD** — ATAPI, signature
   `0xeb140101`, which aborts `IDENTIFY DEVICE` by specification. The first
   command this project ever issued to a SATA controller came back `ABRT`,
   which reads as "the disk said no" when the truth is "that is not a disk".
   Hence `device_kind`, and hence a real `ide-hd` on `bus=ide.0` of the same
   controller so the machine holds one of each and the driver has to tell them
   apart.
2. **NCQ, ever?** Native Command Queuing is what makes AHCI fast and it is a
   second command path. Not in this RFC; the trigger is a measurement showing
   the non-queued path is the bottleneck.
3. **Does `bin/fsd` choose, or does the supervisor?** **Now live, and no longer
   hypothetical.** Two block services answer `block::READ` on the same machine
   as of step 6b — `bin/blkd` on the virtio disk and `bin/ahcid` on the SATA
   one — and nothing yet decides which a filesystem mounts. The deferral's own
   reasoning ("today only one will exist on any given machine") expired the day
   this RFC was accepted. It stays deferred *as a decision*, but it is the first
   thing the next storage RFC has to answer, and it is the reason no filesystem
   has been mounted on this driver yet.

## Implementation plan

1. **The `ahci` crate**: register layouts via `register_block!`, the command
   list, the command table, the H2D FIS, the PRD list, and the `IDENTIFY`
   parser. `#![forbid(unsafe_code)]`, host tests, a fuzz target for the parser.
2. **Discovery and refusal**: find the controller by class/subclass/prog-if,
   ask for a window, and refuse without one — with the boot report saying which.
3. **Bring-up**: handoff, `GHC.AE`, reset, port start, and `SSTS.DET` reported
   per port. No command issued yet.
4. **`IDENTIFY DEVICE`**: the first command, and the first thing the disk says.
5. **`READ DMA EXT`**, and the gate that reads sector zero.
6. **`WRITE DMA EXT`**, and `bin/ahcid` serving `block::READ`/`WRITE` so a
   filesystem can mount on it.
