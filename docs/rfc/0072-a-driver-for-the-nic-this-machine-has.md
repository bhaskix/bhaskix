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

The `bin/ahcid` sequence, applied to a NIC: `iommu::present_for`, `iommu::name`
for the window, map its BAR, spawn a program that attaches, reports what it can
see of the device, and exits. No queues, no traffic.

What this proves is that the containment that works for AHCI works for this
device, on this machine, with bus mastering enabled behind a window it cannot
escape. If step 2 fails, nothing after it is worth writing.

### Step 3 — bring the device up

The part with real risk, and the reason it is its own step. An i40e-class device
is not a register poke: it has firmware, an **admin queue**, and a handshake to
complete before any data path exists. Reset, admin queue, firmware version,
capabilities, link state.

This is where [RFC 0071](0071-drivers-for-hardware-that-already-exists.md)'s
question is settled in practice, and it must be settled **before** this step is
written, not during it: either a port of FreeBSD's BSD-licensed driver for this
device with attribution, or a native implementation from Intel's public
datasheet. Not a reading of the Linux driver.

**Gate:** the boot report states the firmware version and the link state the
device reports. A device that says its own firmware version is a device that is
talking.

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

### Step 5 — one transmit queue

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
