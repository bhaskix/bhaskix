# RFC 0072: a driver for the NIC this machine has

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | drivers / net |
| **Milestone** | Phase 2 — hardware networking |
| **Depends on** | [RFC 0014](0014-driver-framework.md), [RFC 0018](0018-networking.md), [RFC 0049](0049-every-unit-the-firmware-named.md), [RFC 0071](0071-drivers-for-hardware-that-already-exists.md) |

---

## Summary

Bhaskix has a network stack, and on the only physical machine it has ever booted
it has no network. One thing stands in the way: the SR550's NICs are Intel X722s
and the only NIC driver here drives virtio. This proposes `bin/i40ed` — a
single-queue driver for that device, in its own domain, behind the IOMMU that
already contains it.

The arc is deliberately front-loaded with **finding out**: the first step writes
no driver at all, it makes the machine say what is actually on its bus.

## Motivation

`bin/netd` drives virtio-net and nothing else, so every packet this project has
ever moved crossed a virtual device in QEMU. The SR550 has four X722s.

**Until 2026-09-05 that was recorded as one of two blockers.** RFC 0047 said the
SR550 could not be tested on the network for two independent reasons, *"either
sufficient"*: no driver, and its four IOMMU units off. The second was removed by
[RFC 0049](0049-every-unit-the-firmware-named.md) on 2026-08-25 — all four units
programmed, measured on the machine — and that note went stale for eleven days.
Corrected now, and what it leaves is precise: **the driver is the only blocker.**

Everything underneath it is built and proven on that hardware: a device in its
own ring-3 domain, a DMA window through the IOMMU, PCIe/ECAM discovery, register
blocks, and interrupt delivery as a capability. `bin/ahcid` already drives a real
controller — not a virtual one — through exactly that surface, in 1,018 lines.

## Design

Six steps. Each is gated before the next, and the first three answer questions
rather than assuming answers.

### Step 1 — make the machine say what it has

A boot-report line that walks ECAM and prints every function it finds: address,
vendor, device, class, subclass, and whether an MSI-X capability is present.

**No driver, no datasheet, no device knowledge.** Every PCI lookup in this kernel
today is virtio-specific — `virtio::find_nth`, `find_nth_of` — so nothing has
ever printed what is simply *there*. On the SR550 this supplies the X722s' real
identifiers, their BARs and their MSI-X layout, which the rest of this RFC needs
and which **this document deliberately does not state from memory**. A device
identifier written down from recall and wrong is a day lost at step 3.

Useful beyond this RFC: it is the first tool this project has for looking at an
unfamiliar machine, and it costs a walk of config space.

### Step 2 — give one to a domain, and prove containment holds

The `bin/ahcid` sequence, applied to a NIC: find the device, read its register
BAR, create a domain, install the register window as a capability, and ask the
IOMMU to name a DMA window for it.

What this proves is that the containment that works for AHCI works for this
device, on this machine: that `iommu::present_for` answers yes for a function on
bus `b1`, and that `iommu::name` produces a window capability for it. If that
fails, nothing after it is worth writing.

**Amended 2026-09-05: the stub program moves to step 3.** This step first said it
would also spawn a program that attaches, reports and exits. That program proves
domain plumbing, which `bin/ahcid` already proves generally, and it proves
nothing about *this device*. The unknown here is whether the IOMMU contains a
b1-bus NIC, and that is answered entirely in the kernel. Step 3 needs a real
program regardless, so the stub is one there rather than a throwaway here.

**It is inert on QEMU by construction, and that is deliberate.** The only class
02 device on the test lanes is virtio-net, which `bin/netd` already owns, so this
path matches a class 02 function whose vendor is *not* virtio and finds none.
On the SR550 it finds four. A gate that says "no such device here" on every lane
and does the work on one machine is unusual for this project and is the honest
shape: the device only exists in one place.

### What step 2 answered, on the machine, 2026-09-05 — and it inverts the order

Booted. The register half worked exactly as intended:

    nic domain     b1:00.0 8086:37d1 delegated: registers at 0x23ffd000000, 64-bit BAR
    nic domain     no dma window: nothing would contain this NIC, so it was not given one

The BAR is 64-bit and lives at `0x23ffd000000`, well above 4 GiB -- reading it as
32 bits would have named a wrong page silently, which is why that case was
handled rather than assumed.

**The containment half failed, and the reason is a policy, not a defect.**
Elsewhere in the same boot:

    dma untranslated b1:00.0 8086:37d1 passed through deliberately -- it reaches ...

`iommu::pass_through_undrivable` passes through every function that
`iommu::drivable` does not claim, and `drivable` claims exactly three things:
xHCI (class 0c.03, prog-if 0x30), AHCI, and virtio. An X722 is none of them, so
it is deliberately given untranslated DMA, and `iommu::present_for` therefore
answers **no**.

**So the dependency runs the other way from the one this RFC assumed.**
Containment is keyed on *having a driver*, and step 2 was written as though it
could be proven before step 3. It cannot: as long as the NIC is undrivable it is
passed through by design, and a passed-through device is the one thing a window
cannot be named for.

**How big that policy is on this machine: 105 of 115 functions are passed
through.** Ten are drivable or bridges. That is not an argument against the
policy -- an undrivable device that firmware still uses has to keep working --
but it is a much larger surface than the roadmap's IOMMU work implies, and it
was invisible before step 1 counted the bus.

**The fix, and it is a small one.** A device this project *intends* to claim
should be contained rather than passed through, because containing an undriven
device is strictly safer than passing it through: a translated domain with no
mappings lets it reach nothing, while passthrough lets it reach everything. So
`drivable` needs a notion of "claimed" that is broader than "already driven" --
the X722 named, before the driver that drives it exists.

That is step 2's real work, it is a change to `iommu`'s policy rather than to any
driver, and it is what unblocks the rest of this RFC.

### Step 2 is done — the NIC is contained, 2026-09-06

    iommu window   b1:00.0 translating too, a foreign NIC's own page table and domain, 2 in use
    nic domain     b1:00.0 8086:37d1 delegated: registers at 0x23ffd000000, 64-bit BAR
    nic domain     dma window granted; this NIC translates through its own

The X722 has its own page table, its own domain id, and a register window a
domain holds as a capability. Pass-through on that machine fell from **105
functions to 101**, the four NICs no longer among them.

It took two fixes, and the second was in code that was already there.

**`iommu::claimed`.** `pass_through_undrivable` hands untranslated DMA to
anything `drivable` does not claim, and `drivable` claims xHCI, AHCI and virtio.
So containment was keyed on *already having a driver*, and this step could not
precede step 3. `claimed` is a separate predicate -- `drivable` keeps its meaning
for `survey` -- answering whether a device should be contained rather than passed
through. Containing a device nobody drives is strictly safer than passing it
through: a translated domain with no mappings reaches nothing.

**`iommu::windows_on`.** The first attempt attached a correct window and
`verify_window` rejected it. Its invariant compares context entries present in
*one bus's* table against the devices attached to it -- `passed_through(bus)` was
already per-bus for that reason -- but every caller passed the count across *all*
buses. That was right only because every device this project drove lived on bus
`00`. The X722 is on `b1`, so a correct window failed a wrong check, which is the
worse way round: a check that rejects good work is how checks get deleted. All
five call sites count their own bus now, not just the new one.

**Neither fault could have been found in QEMU.** Its devices are all on bus `00`,
where the two counts agree, and it has no undrivable NIC to pass through. The
iommu lane passed before both fixes and passes after them, unchanged.

### Step 3 — bring the device up

The part with real risk, and the reason it is its own step. An i40e-class device
is not a register poke: it has firmware, an **admin queue**, and a handshake to
complete before any data path exists. Reset, admin queue, firmware version,
capabilities, link state.

This is where [RFC 0071](0071-drivers-for-hardware-that-already-exists.md)'s
question is settled in practice, and it must be settled **before** this step is
written, not during it.

**Settled 2026-09-06: native, from Intel's public datasheet.** The X722's
register specification is in the *Intel C620 Series Chipset Platform Controller
Hub Datasheet*, a public download of 3,854 pages, and it carries the registers
this step needs -- `PFGEN_CTRL` and its `PFSWR` reset bit, `GLGEN_RSTCTL`,
`PF_ATQBAL` / `PF_ATQLEN` / `PF_ARQBAL` for the admin queues -- along with the
reset semantics and their ordering against bus-master enable.

Three checks got there, and the first two failed, which is why they are recorded:

* The *X710/XXV710/XL710 datasheet* is public and register-level, and **does not
  cover the X722**. The parts are the same family and not the same document.
* The X722's own public documents are feature-support matrices and product
  briefs, which describe capability rather than registers.
* The C620 PCH datasheet is where the X722's registers actually live, because
  the X722 is the integrated controller in that chipset rather than a discrete
  adapter.

So there is **no licence question to answer here at all**: no GPL source is read,
no clean-room split is needed, and nothing is carried whose provenance would have
to be argued. This is the same route that unblocked
[RFC 0043](0043-an-iommu-on-a-machine-with-no-virtio.md), whose own note reads
*"The Intel VT-d Architecture Specification is a public document; it was fetched
and read, and it answers this directly."*

FreeBSD's `ixl` remains the fallback if the datasheet turns out to omit something
this step needs, and it would be a port with attribution rather than a reading.
Not a reading of the Linux driver, either way.

**Gate:** the boot report states the firmware version and the link state the
device reports. A device that says its own firmware version is a device that is
talking.

### What step 1 answered, on the machine, 2026-09-05

Booted on the SR550. **115 functions**, across buses `00 01 02 07 5a ad ae af b0
b1`. The NICs:

    pci device     b1:00.0 8086:37d1 class 02.00 msi-x
    pci device     b1:00.1 8086:37d1 class 02.00 msi-x
    pci device     b1:00.2 8086:37d1 class 02.00 msi-x
    pci device     b1:00.3 8086:37d1 class 02.00 msi-x

So: device **`8086:37d1`**, at `b1:00.0` through `b1:00.3`, **four separate
functions**, each advertising MSI-X.

That settles unresolved question 3 below — the four ports are four functions, not
one function with four ports, which means **four domains** and not one. It is
also the identifier this RFC refused to write from memory, and it is now a
measurement rather than a recollection.

Two other things the walk showed without being asked, both useful:

* **Two RAID-class controllers**, `00:17.0 8086:2826` and `ae:00.0 1000:0017` --
  the second an LSI/Broadcom part. The storage gap on this machine is a *pair* of
  controllers, which the roadmap's one-line note about "a RAID-mode controller"
  does not convey.
* The kernel already prints `dma unknown ... no driver here, so no window` for
  each of them and for all four NICs, so it sees these devices and declines them
  correctly. Step 2 is about turning one of those refusals into a window.

### Step 3's first half is done — the device resets, 2026-09-06

    nic domain     b1:00.0 8086:37d1 delegated: registers at 0x23ffd000000, 64-bit BAR
    nic reset      the device completed a PF reset; admin queues read 32 and 32 descriptor(s)
    nic domain     dma window granted; this NIC translates through its own

`PFSWR` was set and **hardware cleared it**, which is the datasheet's own
definition of a completed PF reset. That is the first time this project has made
a real network device do anything.

**And the second number is not this code's, which is the more interesting
result.** `RING_DESCRIPTORS` is 32 and it is written only by
`enable_admin_queues`, which the boot never calls -- the wiring resets and reads.
So the device reported admin queue lengths of 32 that **firmware wrote**, and a
PF reset did not clear them. The datasheet gives `PF_ATQLEN` an `Init` of `0x0`,
so "init" there means power-on and not PFR.

Two things follow for the rest of this step:

* **The admin queue setup cannot assume a clean slate.** Something already owns
  these rings -- plausibly the platform, since this NIC is a LOM the firmware
  uses for its own purposes -- and enabling them means taking them over rather
  than starting them. Writing base addresses under a firmware-configured queue
  is how a machine's management path stops working.
* **A reset is not enough to take the device.** The `ATQENABLE` bit is cleared by
  PFR per the datasheet, but the length is not, and neither is whatever firmware
  put in the rings. Step 3's second half has to read the enable bits and decide,
  not assume.

Three defects were found getting here, each by a different mechanism, and none of
them by reading the code again:

* matching *any* non-virtio Ethernet function ran an i40e reset against the
  shell lane's e1000e -- caught by `make test`, before hardware;
* mapping one page of a BAR whose registers reach `0x92400` -- caught by the
  fault handler printing `cr2`, which named the address and therefore the bug;
* verifying a window against every bus rather than its own -- caught by a check
  that rejected correct work.

### The queues are free to take — measured, 2026-09-06

    nic reset  the device completed a PF reset; admin queues read 32 and 32
               descriptor(s), and are disabled -- the reset released them

The question the previous boot raised is answered. The PF reset **does** clear
`ATQENABLE` and `ARQENABLE`, exactly as the datasheet says of that flag, while
the *length* fields keep firmware's 32. So the device arrives with firmware's
sizing and nobody's ownership.

**And the risk that made this worth measuring did not materialise.** This NIC is
a LOM; firmware uses it and the BMC's management path may share it, so a reset
that took the queues could have cut off the console this work reaches the machine
through. It did not: the queues went disabled, the boot completed, and
serial-over-LAN stayed up throughout. That is an observation on one machine and
not a guarantee about every platform, but it is the observation that was missing.

So step 3's second half is unblocked and is what it looked like before the
firmware question appeared: allocate rings, map them into the window step 2 gave
this device, write the base addresses, and set the enable bits last.

One thing it must **not** do is assume the length field is zero. Firmware's 32 is
still there after the reset, so writing an enable bit without writing a length
would enable a queue at somebody else's size.

### Step 3 is done — the device has a command channel, 2026-09-06

    nic reset      the device completed a PF reset; admin queues read 32 and 32
                   descriptor(s), and are disabled -- the reset released them
    nic admin      rings at 0x100000000 and 0x100000400; both queues enabled and read back

The rings sit `0x400` apart, which is 1024 bytes -- 32 descriptors of the 32
bytes Table 38-339 defines -- so the geometry taken off that table is right, and
the device addresses are the ones `iommu::map_memory` returned rather than
physical addresses this NIC could not have reached.

**Both enable bits read back**, which is the part that distinguishes a configured
queue from a write into a device that is not listening.

No exception anywhere in the boot, and the console stayed up while the queues
were taken from a LOM the platform uses -- the risk that was worth a boot to
measure before writing this, and worth confirming again while doing it.

What is *not* done is the rest of what this step's heading promises: a command
has not been posted, so the firmware version and link state are still unread.
That needs a descriptor written into the transmit ring and the tail advanced,
which is the next increment and the first thing this driver will do that the
device has to answer.

### Step 3 is complete — the device answered, 2026-09-06

    nic reset      the device completed a PF reset; admin queues read 32 and 32
                   descriptor(s), and are disabled -- the reset released them
    nic admin      rings at 0x100000000 and 0x100000400; both queues enabled and read back
    nic firmware   the device answered: firmware 3.10

**Firmware executed a command out of a ring this kernel placed.** That is the
step's own gate -- *"a device that says its own firmware version is a device that
is talking"* -- and it is met. Everything before it was a write the hardware
could accept in silence; this is the first exchange where the device had to do
something and say so.

The whole path is Bhaskix's: a device it found by walking ECAM, contained in an
IOMMU domain it created, reset through a register window it mapped, with rings it
allocated and addressed in the device's own translation, and a descriptor it
wrote and a tail it advanced. No exception anywhere in the boot, and the console
stayed up throughout.

**Nothing here came from another driver.** Every offset, flag, opcode and field
offset is cited to its table in the public C620 datasheet, and the two tables
that matter -- 38-340 for the descriptor fields and 38-353 for `Get Version` --
were read as PDF pages because their text extraction is a column of loose digits.
RFC 0071's licence question never had to be answered, because no licensed code
was read.

**Corrected 2026-09-06, the same day: the gate has two halves and the section
above read only one.** Step 3's gate says *"the firmware version and the link
state the device reports"*. The version was read; the link state was not, and the
step was called complete on the version alone. The next boot asked, with
`Get Link Status` (Table 38-63):

    nic link       UP at 1000 Mb/s over 1000BASE-T; media available, signal detected; max frame 9728

So the gate is met in full now, and the half that was missing turns out to be the
one step 4 cannot do without: a receive queue on a port with no link is a queue
that never fills, and this port has link, cable and signal. Recorded here rather
than silently folded into the paragraph above, because the claim was made and a
reader of the history should see that it was made early.

## What step 3 cost, and what found each fault

Four defects, none of them found by re-reading the code:

| fault | found by |
|---|---|
| matching any non-virtio NIC, so an i40e reset ran against an e1000e | `make test`, before hardware |
| mapping one page of a BAR whose registers reach `0x92400` | the fault handler printing `cr2` |
| verifying a window against every bus rather than its own | a check that rejected correct work |
| assuming the admin queues were free | a boot taken to measure it first |

The last one is the one worth keeping. Taking queues from a LOM the platform uses
could have cut the console this work reaches the machine through, and the honest
move was one passive boot to find out rather than a confident write. It cost ten
minutes and the answer changed how the takeover was written.

### Step 4 — one receive queue

A single receive queue pair: descriptor ring in memory the domain owns, buffers
lent to the device through the DMA window, one MSI-X vector.

Single queue is not a shortcut, it is what the framework allows: a ring-3 driver
cannot program its own MSI-X — *"a domain that wedges its own device is its own
problem; one that wedges somebody else's is the kernel's"* — and the kernel's
`Source::MessageSignalled { device, entry }` routes one vector without any change.
Several vectors is an incremental addition to that path and belongs in its own
RFC when throughput justifies it.

**Gate:** a frame sent from the switch arrives, and the boot report prints its
length and EtherType.

#### What step 4 has so far, 2026-09-06

    nic rx queue   queue 0 reads QENA_REQ=0 QENA_STAT=0 -- off, and free to take

Measured before anything is written to it, which is the habit step 3 paid for:
firmware had left the admin queues *sized*, and assuming a clean slate there
would have enabled a ring at somebody else's size. Queue 0 is not in that
position -- both handshake bits are clear, so no handover is needed and the rest
of this step can proceed against a queue nobody owns.

**What is still ahead is the larger part**, and reading the datasheet changed the
estimate. A receive queue is not a ring and a register: *"most of the queue
context parameters are stored in FPM, fetched to an internal cache when
required"*, and that context is 174 bits packed into 25 bytes (Table 38-419). So
Function Private Memory and its HMC programming come before any ring exists,
which is more machinery than steps 2 and 3 together. Enabling is then a request
and a wait -- `QENA_REQ` set, `QENA_STAT` polled -- rather than a write.

**And the register window is now a compile error to get wrong.** It was sized by
a comment twice and faulted twice on this machine: first at `PFGEN_CTRL`
(`0x92400`) against one page, then at `QRX_ENA` (`0x120000`) against a megabyte
whose comment claimed room it did not have. `REGISTER_WINDOW_BYTES` lives beside
the offsets now, with assertions that fail the build if any named register falls
outside it.

#### What step 4 asked before writing anything, 2026-09-06

One boot, every line a question, nothing written to the device that step 3 had
not already written. The answers are what the queue's programming is computed
from:

    nic link       UP at 1000 Mb/s over 1000BASE-T; media available, signal detected; max frame 9728
    nic switch     1 element(s) reported of 1 in the switch
                   VSI  seid 0x018c  uplink 0x0002  downlink 0x0010  connection 1  number 19
                   VSI 19 starts at PF queue 0
    nic queues     this PF owns absolute queues 0..=383, 384 pair(s); PXE mode still set
    nic fpm        function 0: segment descriptors 0..+16 at 2 MB each; object sizes tx 2^7 rx 2^5 bytes; queue max 1536
    nic fpm        LAN registers as left: tx base 0 count 0, rx base 0 count 0 -- bases in 512-byte units, and this driver's to write
    nic rx queue   absolute queue 0 reads QENA_REQ=0 QENA_STAT=0 -- off, and free to take
    nic hmc        no error recorded

Five facts, each of which the code would otherwise have had to assume:

* **The port is live** -- link, media and signal, at 1 Gb/s on copper. A frame
  can arrive.
* **Frames are steered to VSI 19, SEID `0x18c`, and its queues start at this
  PF's queue 0.** A received frame reaches a *VSI* first and the VSI's
  `VSILAN_QBASE` says which queue; a driver that took queue 0 without asking
  would have been right here by luck. The Set VSI Promiscuous Modes command,
  which is how the datasheet says broadcast is forwarded, wants the SEID.
* **This PF's first absolute queue is 0**, so its queue 0 and the device's queue
  0 are the same queue, and `QRX_ENA[0]` was the right register to have read.
  On the other three functions that will not be so, which is why the number is
  read from `PFLAN_QALLOC` and not assumed.
* **The device is still in PXE mode** -- the flag a core reset sets and only the
  Clear PXE Mode command clears. It changes the queue-length rule (a multiple of
  32 outside it) and the tail granularity (eight descriptors), so it is cleared
  first.
* **The four LAN private-memory registers read zero, and they are software's to
  write.** The uncommitted first draft of this reading called `GLHMC_LANRXBASE`
  and `GLHMC_LANRXCNT` read-only and firmware-assigned, on the strength of the
  register heading, which says RO. The field tables say RW, and 38.26.3.1 says
  in words: *"Host software is responsible for setting up the GLHMC_{object}CNT
  and GLHMC_{object}BASE registers for LAN objects."* The prose corrected the
  code before any boot had to, and the zeros confirm it. `GLHMC_SDPART` -- the
  segment descriptor range -- is the one that really is firmware's, and this
  function has sixteen segments, 32 MB of private memory space, of which one
  page will be backed.

**Two things this boot did not do.** It did not print a frame -- that is the
gate, and it needs everything the next increment builds. And it did not verify
Table 38-419's two ambiguities on hardware; they were settled by the datasheet's
own worked example instead. The table gives the ring base *"in 12-byte units"*
while its example only decodes to a page-aligned address in 128-byte units; and
the example sets a bit the table calls reserved. The encoder reproduces the
example bit for bit under host test, and the hardware boot is what will say
whether the example was right.

**What the boot cost to read: one general command path.** `Get Version` had been
a one-off with the descriptor bytes poked by hand; a second command was the
moment the commit message said to build a typed descriptor, and it was built --
eight words, Table 38-340's byte numbering, a ring position that advances, and
a buffer flag for the one indirect command here. The unsafe line count went
*down* by one.

#### The queue comes up and no frame arrives — step 4's gate is NOT met, 2026-09-06

The second boot built the queue. Everything the device will confirm without
traffic is correct, and the one thing the step exists to show did not happen:

    nic pxe        cleared: the device left PXE mode; GLLAN_RCTL_0.PXE_MODE reads 0
    nic fpm        programmed tx base 0 count 384, rx base 96 count 384; read back tx 0 / 384, rx 96 / 384 -- as written
    nic fpm        receive context 0 at private address 0xc000: segment 0, page descriptor 12, offset 0; the layout ends at 0xf000, 15 page(s)
    nic hmc        segment 0 -> page descriptor page at 0x100001000, 15 backing page(s); page descriptor 12 -> 0x100002000; the segment reads back as written
    nic rx ring    32 descriptors at 0x100003000, 16 posted with 4096-byte buffers from 0x100004000; frames up to 1536 bytes
    nic filter     VSI seid 0x18c now forwards multicast and broadcast to its queues
    nic rx armed   with the queue still disabled, no descriptor completed in 100 ms
    nic rx queue   absolute queue 0 enable requested; QENA_STAT set (REQ=1 STAT=1)
    nic rx frame   FAILED: no frame in 5 s with the queue enabled and the link up
    nic rx context the device holds head 1, base 0x8fb0f000 (NOT this ring), qlen 0; CTX_MISS -- not resident
    nic hmc        no error recorded
    nic rx queue   disabled again: QENA_STAT clear

**The gate is a frame arriving, and no frame arrived. The step is not done.**
That is the headline, and nothing below softens it.

**What the boot does establish**, none of it previously tested on hardware:

* **The FPM arithmetic is right on the machine, to the digit.** Every number the
  report printed is what the host tests compute from 38.26.4 and Table 38-337:
  a receive base of 96 (512-byte units) after 384 transmit contexts of 128
  bytes, context 0 at private address `0xc000`, segment 0, page descriptor 12,
  offset 0, a layout ending at `0xf000` and spanning 15 pages. The four LAN
  registers **read back as written**, which also settles the read-only question
  the first draft got wrong: they are software's.
* **The segment descriptor round-trips.** Written through `PFHMC_SDCMD` and read
  back through the same register, identical. A write past this function's range
  *"is dropped"* silently, so the read-back is the only proof it landed, and it
  did.
* **The HMC recorded no error.** An invalid segment or page descriptor, or an
  object index past its count register, sets `PFHMC_ERRORINFO`. Nothing did.
* **The device accepted the queue.** `QENA_STAT` followed `QENA_REQ`, which
  38.30.3.3.2 says happens *"not more than 10 µs"* after the request, and the
  queue disabled cleanly afterwards.
* **The negative arm held.** With everything in place but the enable, descriptor
  zero was watched for 100 ms and stayed untouched. So the frame line, when one
  finally prints, cannot be a completion the device wrote for some other reason.
  This is the arming the testing plan asks for, and it is *in the boot* rather
  than in a separate run.
* **The console survived**, the boot reached its shell, lock-order checking was
  clean over 529,240 acquisitions, and no exception fired anywhere.

**Why no frame — and the honest answer is that this boot cannot say.** Two
readings survive, and they are distinguished by a cheaper experiment than either
would suggest:

1. **The wire is quiet.** Five seconds is a short window on an enterprise access
   port. Spanning-tree BPDUs arrive about every two seconds *if* the switch
   sends them to this port, LLDP every thirty, and a port with no other host
   behind it may carry no broadcast at all in five seconds. The link is up with
   media and signal, which proves a cable and a partner, **not** that anything is
   being sent to this port.
2. **The receive path is not receiving.** The context may not have been fetched
   from the backing page, the filter may not actually forward to this queue, or
   the descriptors may not be where the device looks.

**The context read-back is not evidence for either, and it would be easy to
misread as evidence for the second.** `CTX_MISS` means the queue *"was not
resident in the context cache"* at the moment of the read -- so the four words
returned beside it describe whatever line the cache held, not this queue. A base
of `0x8fb0f000` with `qlen 0` is therefore an artefact of asking a cache that had
nothing, not a device pointing at somebody else's ring. Recorded because the line
is printed and the next reader will see it: **it says less than it appears to.**

**The next instrument is one longer window, not one more theory.** Raise the wait
from five seconds to a minute and re-boot. If a frame lands, reading (1) was
right, the path works, and the gate is met by a change of one constant. If sixty
seconds of a live 1 Gb/s port produce nothing, reading (2) is real and the
investigation has somewhere to go: the queue context can be programmed directly
through `PFCM_LANCTXCTL` instead of through FPM -- the datasheet's own pre-boot
path, bypassing the HMC entirely -- which splits "the context is wrong" from "the
FPM plumbing is wrong" in a single boot.

That is deliberately not done here. A second reboot of a live cluster node to
change a timeout is worth asking for rather than assuming, and a five-second
negative is too weak to build the next fix on.

#### A minute, and the device is running this driver's queue — still no frame, 2026-09-06

The window went to sixty seconds and the ring gained a full scan. The gate is
**still not met**, and almost everything else changed:

    nic rx armed   with the queue still disabled, no descriptor completed in 100 ms
    nic rx queue   absolute queue 0 enable requested; QENA_STAT set (REQ=1 STAT=1)
    nic rx frame   FAILED: no frame in 60 s with the queue enabled and the link up
    nic rx ring    none of the 16 posted descriptors completed, so the ring is untouched rather than filled elsewhere
    nic rx context the device holds head 4, base 0x100003000 (this ring), qlen 32; resident in the cache
    nic hmc        no error recorded

**The context line is the result.** In the five-second boot it read
`base 0x8fb0f000 (NOT this ring), qlen 0; CTX_MISS`. It now reads **this ring**,
`qlen 32`, resident. So:

* **The whole HMC path works.** The device fetched a queue context out of a
  backing page this kernel allocated, named through a page descriptor this
  kernel wrote, in a segment this kernel programmed, and it came back holding
  the ring address and length this kernel put there. Every layer between
  `PFHMC_SDCMD` and the device's context cache is carrying real data. That is
  the machinery step 4 said would be *"more than steps 2 and 3 together"*, and
  it is working.
* **Table 38-419's disputed `BASE` units are settled, on hardware.** The table
  says *"12-byte units"*; the encoder used 128 because only that made the
  datasheet's own example decode to a page-aligned address. The device now
  reports a base which, multiplied by 128, is exactly the ring's device
  address. **The example was right and the table's text is wrong**, and this is
  a measurement rather than a reading.
* **The earlier `CTX_MISS` caveat was correct.** The previous section said that
  read *"says less than it appears to"* and described an unrelated cache line.
  The same read taken later returns the truth, which is what a stale cache line
  looks like from the other side. Kept as written.

**`head 4`, and what it does and does not prove.** The head has moved off zero,
so the device is not idle with respect to this ring -- it is operating on the
descriptors. It does **not** prove four packets arrived, and the table says so
itself: *"During dynamic operation it is not guaranteed that all descriptors
below the head complete."* Descriptors are prefetched in cache-line batches
before any packet needs them. With every one of the sixteen scanned and none
carrying `DD`, the reading that fits is a prefetch that ran ahead, not four
completions that went missing.

**Three explanations are now dead**, each by a measurement rather than an
argument:

| was possible | why it is not |
|---|---|
| the context never reached the device | it is resident and holds this ring |
| the write-back was refused by the IOMMU | the only bring-up fault is the long-known xHCI one at `0xaa95f000`; the NIC caused none |
| a frame landed at an index nobody watched | all sixteen scanned, none completed |

**What is left is narrow: does this port receive anything at all?** Sixty
seconds of a live 1 Gb/s port with promiscuous multicast and broadcast set on
its VSI produced nothing, which makes *"the wire is quiet"* much less
comfortable than it was at five seconds -- but it does not kill it, because
nothing here has yet asked the device how many frames its **port** has seen, as
distinct from how many reached this queue.

**That is the next instrument, and it is read-only.** The device keeps receive
statistics per port and per VSI -- 38.30's LAN initialisation flow has a driver
read them all at start-up precisely because *"the values of these counters is
the baseline for any statistics collected later"*, and `GLV_REPC` counts frames
a VSI dropped for exceeding `RXMAX`. One boot that prints them splits the two
remaining worlds cleanly:

* port counters moving while the queue stays empty ⇒ frames arrive and the
  **steering or filtering** is wrong, and the VSI/queue mapping is where to
  look;
* port counters at zero ⇒ **nothing is being sent to this port**, the driver may
  be correct as written, and the gate needs a switch that talks or a frame this
  machine provokes -- which is step 5, and would make the two steps one.

No further boot was taken. Three reboots of a live cluster node in a morning is
enough, and the statistics reading is a change worth making deliberately rather
than at the end of a session.

#### The counters answer it: the port receives, the queue does not — 2026-09-06

The statistics registers were added and a fourth boot read them either side of
the same sixty-second window:

    nic stats      port 0 baseline: 21 packet(s) received since power-on (0 unicast, 21 multicast, 0 broadcast), 0 discarded
    nic rx frame   FAILED: no frame in 60 s with the queue enabled and the link up
    nic rx ring    none of the 16 posted descriptors completed, so the ring is untouched rather than filled elsewhere
    nic stats      port 0 over the window: 4 packet(s) (0 unicast, 4 multicast, 0 broadcast), 606 octet(s), 0 discarded
    nic stats      VSI 19 over the window (index assumed to be the VSI number): 0 packet(s), 0 discarded
    nic stats      the port saw traffic and this queue got none -- steering or filtering, not a quiet wire

**The quiet-wire reading is dead.** Four frames entered this port during the
window and none reached the queue. `GLPRT_RDPC` is zero, so the port did not
discard them either -- they were received cleanly and went somewhere that is
not here.

**And the traffic has a shape worth reading carefully.** Since power-on this
port has seen **21 packets, every one of them multicast** -- not a single
unicast frame and not a single broadcast, ever. Four arrived in sixty seconds,
averaging 151 bytes. That is the signature of switch control traffic on a
segment with no hosts conversing: spanning-tree and discovery frames at a few
per minute, and nothing else at all.

**Which makes the leading explanation one where this driver is not at fault**,
and it deserves to be stated before anybody hunts a bug:

* **The frames may be ones no host VSI is ever given.** Reserved multicast
  destinations -- spanning tree at `01:80:C2:00:00:00`, LLDP at
  `01:80:C2:00:00:0E` -- are consumed by a bridge rather than forwarded, and
  this port's internal switch is a bridge. If the only frames arriving are
  exactly the class that never reaches a host, a perfectly correct driver sees
  nothing, forever, on this wire.
* **Or the steering really is wrong**: the promiscuous setting did not take
  effect, this VSI is not the default VSI for unmatched traffic, or the VSI's
  queue mapping is not what `VSILAN_QBASE` implied.

The boot report's own verdict line says *"steering or filtering"*, and that is
accurate for both readings -- the frames are being steered away from this queue.
What it does not say, and what this section does, is that being steered away may
be the **correct** behaviour for the only frames this segment carries.

**So the queue cannot be proven by waiting; it has to be provoked.** Nothing on
this wire is addressed to this machine, so no amount of listening will produce a
frame that is. The tests that would settle it, cheapest first:

1. **Ask for the VSI's real statistics index.** The `0 packets` above is read at
   the VSI's *number*, and the datasheet assigns a statistics set when a VSI is
   added -- firmware added this one. Get VSI Parameters returns the true index
   and turns that line from an assumption into a measurement.
2. **Make this VSI the default VSI**, Table 38-253's flag 3: *"accept packets
   within the switch ID not matching any specific address to this VSI"*. If
   frames are being dropped for matching no filter, this is the one bit that
   changes it.
3. **Send something and make the wire answer.** That is step 5, and this result
   argues for doing it *before* finishing step 4 rather than after: an ARP
   request out of this port draws a reply addressed to this port's own MAC, and
   a unicast frame aimed at us is the one thing this segment has never carried.

**Step 4's gate stays open, and step 5 is now the way to close it.** That is a
change to this RFC's order and it is made on evidence: the receive path is built
and the device is running it, and the only thing missing is a frame that was
meant for this machine.

**What four boots have established, and none of it was testable in QEMU:** the
device resets, answers commands, reports its link and its switch, hands over its
queue allocation, runs a queue context this kernel wrote through the host memory
cache, prefetches from a ring this kernel posted, and counts what its port
receives. What is unproven is one step: a frame crossing from the port into the
queue.


### Step 5 — one transmit queue

#### A frame left, and the port's own MAC counted it out — 2026-09-06

Built and run on the SR550, in the same boot as the receive attempt so that
anything coming back would land in a ring that was still posted:

    nic vsi        seid 0x18c is VSI number 12, queue set handle 0x0 -- RDYList 0
                   the switch reported VSI number 19 and this reports 12 -- the statistics index above was read at the switch's
    nic mac        port 0 station address 08:94:ef:7a:fc:8e
    nic tx context queue 0 context at private address 0x0 (page descriptor 0, offset 0), ring 0x100005000, 8 descriptors
    nic tx queue   queue 0 owned by PF 0 and enabled: QENA_STAT set (REQ=1 STAT=1)
    nic tx frame   60 bytes to its own address: the device reported the descriptor done, head 0
    nic tx frame   60 bytes to broadcast: the device reported the descriptor done, head 1
    nic tx stats   port 0 sent 1 packet(s) (0 unicast, 0 multicast, 1 broadcast), 64 octet(s)
    nic rx after   still nothing in the receive ring after transmitting

**A frame this machine built left through the port's MAC.** One broadcast
packet, 64 octets -- the sixty bytes written plus the four-byte CRC the device
appends -- counted by `GLPRT_BPTCL`, which is the MAC's own accounting and not
this driver's. Every layer under it is Bhaskix's: a queue set handle asked of
firmware, a station address read from the NVM, a 128-byte transmit context
written into a backing page named through a page descriptor in a segment this
kernel programmed, the queue's internal disable flag cleared, its owning
function stated in `QTX_CTL`, the enable handshake answered, a descriptor posted
and a doorbell rung, and the completion written back into the ring.

**The gate is not strictly met, and the reason is the wire rather than the
driver.** It asks for a reply *"observed by the host rather than claimed by the
guest"*. What exists is stronger than a guest's claim -- the MAC counted the
frame out -- and weaker than the gate: nothing outside this machine confirmed
receiving it, and nothing answered. Five boots have now shown this port has
never taken in a single unicast or broadcast frame, so there may be no host on
that segment to observe anything. **The mechanism is demonstrated; the
external witness the gate wants is not available where this machine is
plugged in.**

**Three measured results worth more than the headline:**

* **The self-addressed frame went nowhere.** A frame sent to this port's own MAC
  completed its descriptor, was **not** counted out as unicast, and did **not**
  come back into the receive ring. The internal switch neither transmitted it
  nor looped it back, so the loopback route to proving both directions inside
  one machine is closed. It was worth trying: it would have needed nobody else's
  cooperation.
* **The VSI number is not what the switch element said**, and this matters
  backwards. `Get Switch Configuration` reports element-specific field 19;
  `Get VSI Parameters` reports VSI number **12** for the same SEID. The per-VSI
  statistics in the previous section were read at 19. **That reading is
  therefore suspect**, and the "VSI got 0 packets" line beside it should not be
  relied on -- which is exactly what its own "index assumed" label was for. The
  port counters and the empty ring are unaffected, and they are what the
  previous section's conclusion rests on.
* **The queue set handle read `0x0`** and the queue enabled and transmitted
  anyway. Either queue set zero really is this VSI's, or `RDYList` is not
  consulted for a configuration this simple. Recorded as working-but-unexplained
  rather than dressed up either way.

**What this leaves.** Transmit works. Receive is built, running, and has never
been handed a frame. The next thing that would settle it is a frame deliberately
aimed at `08:94:ef:7a:fc:8e` from a machine on that segment -- which means
finding out what that segment is, and is a question about cabling rather than
about this driver.

#### What network is that port on, and where the frames actually stop — 2026-09-06

Two questions were asked of the machine rather than of the driver: which
network this port is plugged into, and — once the VSI number was corrected —
where the frames stop.

**The port is identified beyond doubt, and two candidate networks are ruled
out.** The BMC's own inventory names it independently of anything this driver
reads:

| | |
|---|---|
| adapter | `Intel X722 LOM (onboard)`, Redfish `ob-4` |
| this function | physical port 1, `NIC1` |
| MAC | `08:94:EF:7A:FC:8E` — the same address the driver read from the NVM |
| link | up, 1 Gb/s, all four ports up |
| addresses | none configured, by anything |

* **Not the management network.** The BMC's interface reports
  `InterfaceNicMode: "Dedicated"`, MAC `08:94:ef:7a:f4:bf` on `10.5.5.103/24`.
  It does not share this LOM, so the X722 is not on the segment the console
  arrives over.
* **Not this workstation's segment.** `tcpdump` on `10.17.17.0/24` watched for
  `08:94:ef:7a:fc:8e` across a whole boot -- the boot in which the machine
  transmitted a broadcast ARP -- and saw **nothing**. The frame left the port's
  MAC and did not arrive here, so the two are not in one broadcast domain.
* **The BMC knows nothing more.** Its Redfish port records carry link speed and
  MAC and no LLDP neighbour, no VLAN, no management address.

**So the segment is a third one, and its traffic describes it.** Across five
boots this port has taken in **21 packets, every one multicast**, at about four
a minute and 151 bytes each -- and *no unicast and no broadcast, ever*. That is
a switch port with no other host conversing on it, carrying only control-plane
multicast. **Naming it needs one of those frames read**, which is why the hex
dump was added: LLDP carries the neighbour's system name, port and management
address as TLVs, and one captured frame would answer the question outright.

**And correcting the VSI number moved the fault a whole layer.** The switch
element's field says 19; `Get VSI Parameters` says **12** for the same SEID,
and the per-VSI statistics are indexed by the number:

    nic stats      port 0 over the window: 4 packet(s) (0 unicast, 4 multicast, 0 broadcast)
    nic stats      VSI 12 over the window: 4 packet(s), 0 discarded
    nic rx ring    none of the 16 posted descriptors completed

At index 19 that middle line read `0`. At the right index it reads **4** -- the
same four frames the port took in. **The frames reach the VSI.** They stop
between the VSI and the queue, and the previous section's conclusion is
corrected accordingly: it was right that the queue got none and wrong to leave
the impression the VSI never saw them.

**What that leaves, and the one counter that would settle it.** The VSI's queue
base reads 0 and the queue enabled was 0, so the obvious mapping is right. Two
readings remain: the VSI spreads frames across several queues by hash and only
queue 0 is enabled, or the queue context is right in every field this driver
checks and wrong in one it does not. The datasheet names the counter that
distinguishes them -- *"packets received to invalid queues are dropped and
counted by the GLV_REPC counter"* -- and **`GLV_REPC` has no register
definition in this document**: three mentions in prose and no entry in
38.39.2.16. That is a gap in the datasheet rather than in the reading, and it
is written down because the obvious next instrument turns out not to exist
here.

#### The wire is a LACP aggregate, and that explains all of it — 2026-09-06

The cabling was described after the seventh boot: **the four ports are a trunk
with VLANs, aggregated with LACP**, and VLAN 17 carries a network with DHCP on
it. Two boots were spent on that information before it arrived, and both are
worth keeping because of what they eliminate.

**Boot seven: eight queues, and promiscuous VLAN.** The reading before it was
that the VSI spreads frames across its queues by hash and only queue zero was
enabled. Eight queues were set up and enabled -- eight is what fits, since
`QLEN` must be a whole multiple of 32 and eight 512-byte rings are one page --
and `Set VSI Promiscuous Modes` gained its **VLAN** flag, without which the
multicast and broadcast flags are scoped per-VLAN and a tagged frame is counted
at the VSI and dropped.

    nic rx queue   absolute queues 0..=7 enabled: 8 answered QENA_STAT
    nic rx frame   FAILED: no frame in 60 s in any of the 8 queues, with the link up
    nic stats      port 0 over the window: 4 packet(s) ... VSI 12: 4 packet(s), 0 discarded

**All eight enabled, none filled.** Both hypotheses dead in one boot.

**Boot eight: a DHCP DISCOVER tagged for VLAN 17**, built by `bhaskix-net` --
the crate the network services use -- with the 802.1Q tag written by hand
because that crate writes untagged headers.

    nic tx frame   290 bytes, a DHCP DISCOVER on VLAN 17: the device reported the descriptor done
    nic tx stats   port 0 sent 2 packet(s) (0 unicast, 0 multicast, 2 broadcast), 354 octet(s)
    nic rx after   nothing in any receive ring in 10 s after transmitting, the DHCP DISCOVER included

The frame was built, posted, completed, and **counted out of the port's MAC**.
Nothing answered.

**LACP is why, and it accounts for every observation across eight boots.** A
switch running 802.3ad keeps a member port *unselected* until the host
participates in the protocol. An unselected member carries control-plane frames
and no data. So:

| observation | what LACP says about it |
|---|---|
| no unicast or broadcast **ever** received, in eight boots | the switch is not forwarding data to an unaggregated member |
| ~4-5 multicast per minute, ~150 bytes | LACPDUs: EtherType `0x8809` slow protocols, 124-byte payload, tagged |
| the VSI counts them and no queue gets them | they go to `01:80:C2:00:00:02`, a reserved address a bridge terminates rather than forwards |
| a DHCP DISCOVER drew no reply | the switch will not forward data on, or accept it from, an unselected member |
| all four ports link-up, none carrying data | four members of a LAG that has never formed |

**So the receive path is probably not broken.** That is the most useful thing
eight boots produced, and it took the cabling to see it: the driver programs a
context the device fetches, posts descriptors the device prefetches, and waits
on a wire that has no deliverable traffic to give it. Every "FAILED" line above
is the gate reporting a fact about the network, not a defect in the code -- and
the gate was right to keep failing, because a driver that had *claimed* success
here would have been wrong.

**What would finish step 4, in order of cost.** Neither is done, and the first
is not this project's to do:

1. **One switch-side change.** A single member configured as a plain access or
   trunk port, outside the aggregate, and the existing driver should receive
   immediately -- the queue is already built, enabled and waiting.
2. **Speak LACP.** 802.3ad in Bhaskix: a state machine, periodic PDUs on all
   four ports, and aggregation logic. That belongs in a service above the
   driver, not in this RFC, and it is a larger piece of work than steps 4 and 5
   together.

**A warning that goes with the second.** Emitting LACPDUs from one member while
the other three stay silent would half-form an aggregate on a live cluster
switch. This machine is a production node; that is a change to make
deliberately, with the network's owner, and not as the next experiment.

#### The original step, for the record

The other half. A frame this machine builds leaves the wire.

**Gate:** an ARP reply, or an ICMP echo reply, observed *by the host* rather than
claimed by the guest. The guest saying it transmitted is not evidence that
anything left.

### Step 6 — behind `bin/ipd`, as a second backend

The stack above does not learn a new device. `bin/netd` and `bin/i40ed` present
the same interface to `bin/ipd`, and the machine picks whichever it has.

**Gate:** the existing network gates — UDP, TCP, IPv6, DHCP — run on the SR550
against this driver. That is the point of the whole RFC: those gates have only
ever run in QEMU.

## Alternatives considered

**Wait for a machine with a virtio NIC.** Cheapest, and it postpones the problem
forever. The SR550 is the hardware this project has.

**Write for the RAID-mode storage controller first.** The other SR550 gap. Storage
has a working path on that machine already (`bin/ahcid` drives its SATA
controller); the network has none, and the network gates are the larger body of
untested work.

**Multi-queue from the start.** Rejected for now: it needs a kernel change to the
MSI-X claim path, and a first driver should be judged on whether a packet moves.

## Impact on existing design documents

* `docs/roadmap.md` — the networking bullet says *"nothing here has run on
  physical hardware and currently cannot"*. Step 6 is what changes that sentence,
  and it should not be edited before then.
* `docs/rfc/0047-...` — its stale two-blocker note is already corrected.
* `TRACKER.md` §4 and §7.
* `docs/security.md` — a second device driver holding a DMA window; the threat is
  the one RFC 0049 already prices, not a new one.

## Security implications

None new, and that is the result of work already done. The driver runs in ring 3,
in its own domain, with a DMA window it cannot address outside — the containment
RFC 0049 built and measured on this machine. A defect in it reaches its own
device and the capabilities it was handed.

If step 3 is a port, the code arrives from outside and must be read rather than
adopted. Provenance — upstream revision, SPDX headers, attribution — is recorded
at the commit that carries it.

## Performance implications

Unmeasured and deliberately unbudgeted. One queue pair on a 10G part will not
approach line rate, and the first number that matters is *one packet*, not
throughput. Multi-queue is a later RFC with its own numbers.

## Testing plan

QEMU cannot test this: it has no X722 model. That is unusual for this project and
must be said plainly — **the gates for steps 3 to 6 run on the SR550 or nowhere.**

Steps 1 and 2 are testable in QEMU (enumeration prints whatever the emulator has;
containment can be proven against a virtio device), and steps 3 to 6 are hardware
gates, run over serial-over-LAN as every SR550 boot has been.

Armed, each of them: a step whose gate cannot fail has not been tested. The
receive gate must be shown red with the queue disabled, and the transmit gate red
with the ring not posted.

## Unresolved questions

1. **Which licence route**, settled before step 3 is written and not during it.
2. **What the SR550's X722s actually report** — step 1 answers this, and every
   later step depends on it.
3. **Whether the four ports share one function or present four**, which changes
   how many domains this needs.
4. **Firmware expectations.** i40e-class devices can require a firmware image or a
   particular version. If this device needs one the SR550 does not carry, that is
   a blocker this RFC cannot resolve, and step 3 is where it would surface.

## Implementation plan

1. ECAM enumeration in the boot report. QEMU gate, then read on the SR550.
2. Device granted to a domain with a DMA window; a stub that attaches and reports.
3. Bring-up: reset, admin queue, firmware version, link. **Licence route decided
   first.**
4. One receive queue, and a frame arrives.
5. One transmit queue, and a frame leaves — verified by the host.
6. Behind `bin/ipd`; the existing network gates run on hardware.
