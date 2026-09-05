# RFC 0071: drivers for hardware that already exists

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | drivers / architecture |
| **Milestone** | Phase 2 and beyond |
| **Depends on** | [RFC 0001](0001-license-apache-2.0.md), [RFC 0014](0014-driver-framework.md), [RFC 0031](0031-linux-compatibility-as-an-adapter.md), [RFC 0049](0049-every-unit-the-firmware-named.md) |

---

## Summary

Bhaskix drives four device families and the world has thousands. This RFC does not
propose a driver; it proposes a **position on where drivers come from**, because the
project has never recorded one, and every month without it is a month of writing
device support by hand at a rate no team can sustain.

It recommends a tiered answer: keep writing native drivers for the small set that
matters, port from **permissively licensed** sources where one exists, and build
toward running an unmodified driver in a **domain with the device passed through**
for everything else. It recommends against porting Linux drivers into Bhaskix
services, on two independent grounds the project has already accepted elsewhere.

## Motivation

### The gap is not theoretical, and one machine measured it

`bin/blkd` drives virtio-blk, `bin/ahcid` drives AHCI, `bin/netd` drives
virtio-net, and the kernel drives a 16550, an i8042 and an xHCI. That is the whole
inventory.

The SR550 — the only physical machine this system has ever booted on — needs none
of them:

| what the machine has | what Bhaskix has |
|---|---|
| four Intel X722 NICs | a virtio-net driver, and nothing else |
| disks behind a RAID-mode controller | `bin/ahcid`, which refuses that mode by name |
| an xHCI whose port 1 will not answer `SET_ADDRESS` | an xHCI driver that cannot get past it |

One server, three device classes, zero coverage. The IOMMU work
([RFC 0049](0049-every-unit-the-firmware-named.md)) is accepted and measured on that
hardware, so the *containment* half of driving real devices is built. What is
missing is the drivers themselves, and they are missing one device at a time.

### Writing them is the current plan, and it is not a plan

[RFC 0014](0014-driver-framework.md) made the second driver cheaper than the first
and it succeeded at that — PCIe/ECAM, register blocks, a driver in its own domain
behind an IOMMU, reachable only through a capability. It is a good framework. It
does not change the arithmetic: a new device family is days to weeks of work, the
device count grows faster than any team, and a system that cannot boot on the
hardware people own is a system nobody runs.

**This is the largest open strategic question in the project and it is not written
down anywhere.** No mention of driver reuse, porting, or provenance appears in
`architecture.md`, `roadmap.md`, or RFC 0031. The roadmap's honest-gaps paragraph
implies native-only forever without ever saying so.

## Design

Four sources of device support, and what each costs here.

### A. Native drivers, written for Bhaskix

What happens today. Correct by construction, idiomatic, `no_std`, host-testable
where the design allows. Unbounded cost per device.

**Keep for:** the platform minimum — serial, timers, interrupt controllers,
i8042 — and any device where the driver is small or the semantics matter enough
to own. These are written once and rarely change.

### B. Port from permissively licensed sources

BSD-licensed drivers (NetBSD, FreeBSD, OpenBSD) and permissive userspace
poll-mode drivers (DPDK, SPDK) can be relicensed into an Apache-2.0 tree with
attribution. No licence conflict, and no architectural conflict either: a
poll-mode userspace NIC driver is *already the shape Bhaskix uses* — a ring-3
program, a device behind an IOMMU, memory it owns and lends.

**This is the underrated option.** The SR550's X722 has a well-tested BSD-licensed
driver (`ixl`/`ixgbe` family) and a DPDK poll-mode driver. Either is a legitimate
starting point for the exact gap that blocks hardware networking today.

### C. An unmodified driver in a domain, device passed through

Run the driver where it already runs — inside a Linux (or BSD) guest in a domain —
give that domain the device through the IOMMU, and expose the result as an
ordinary Bhaskix service behind a capability. The guest is a **domain like any
other**: the settled architecture decision is that *containers and VMs are the same
primitive*, and this is the case that decision was made for.

This is how the driver problem is solved in practice elsewhere, and it composes
with everything already built: per-device IOMMU containment (RFC 0049), drivers in
ring 3, services behind capabilities.

**Cost, stated plainly: it needs a hypervisor, and there is none.** `kernel/src/vm.rs`
is address spaces, not virtual machines — no VT-x, no EPT, no guest entry. That is
a large, multi-RFC build. This RFC proposes it as the direction, not as work to
start now.

### D. Port Linux drivers into Bhaskix services — recommended against

A shim that presents enough of the Linux driver API to run `drivers/net/…`
unmodified inside a Bhaskix service. Rejected on two independent grounds, each
already recorded here -- the first in an accepted RFC, the second in a draft that
this project treats as its strategic frame:

**Licence.** [RFC 0001](0001-license-apache-2.0.md) chose Apache-2.0 and its own comparison
table rejects GPLv2 partly because *"it is incompatible with Apache-2.0"*. Linking
GPL-2.0 driver code into an Apache-2.0 service is that incompatibility, in the
direction that matters. Option C keeps the same code at arm's length across a
domain boundary instead, which is the standard way this is handled.

*This is a licence question, not a licence opinion: before any GPL-derived code is
carried in any form, it needs counsel, not an RFC.*

**Architecture.** [RFC 0031](0031-linux-compatibility-as-an-adapter.md) is a *draft*
and is nonetheless the frame every Linux decision here has been made against. It
states the shape of Linux compatibility: *"an adapter above Bhaskix services, never a reason to
reproduce Linux"*, and the framing of Bhaskix as *"a complete Linux replacement,
never a Linux reimplementation"*. A Linux driver-API shim inside a service is a
Linux reimplementation inside a service — the precise thing that principle
forbids. It was written about syscalls; nothing about it is specific to syscalls.

## Alternatives considered

**Do nothing and keep writing drivers.** The status quo, and the honest reading of
the roadmap today. Rejected as a *recorded position* rather than as work: native
drivers continue under option A, but "native only" cannot be the whole answer and
should not be the answer by default.

**Depend on virtio everywhere.** Works, and is why everything runs in QEMU. It is
also why nothing runs on the SR550: real servers do not present virtio NICs.

**A stable in-kernel driver ABI so third parties ship binaries.** Wrong shape for
a capability system, and it commits to an interface far too early.

## Impact on existing design documents

* `docs/roadmap.md` — its honest-gaps paragraph should say where drivers come from
  rather than leaving native-only implied.
* `docs/architecture.md` §8 — this is an architecture question and belongs in the
  settled/open table.
* `docs/rfc/0014-driver-framework.md` — unchanged; it governs option A and B
  equally, and a ported driver lands in the same framework.
* `docs/security.md` — option C adds a threat surface worth pricing before it is
  built, not after.

## Security implications

Option B inherits code written for a different threat model. A ported driver runs
in ring 3 behind an IOMMU, which bounds what a defect in it can reach — that is
exactly why the containment work came first — but it does not make the code
trustworthy, and it must be read rather than adopted.

Option C is the interesting one. A driver VM holds a real device and speaks to
Bhaskix services; a compromise of it reaches whatever its IOMMU domain allows and
whatever capabilities it was handed, and no more. That is a *smaller* blast radius
than a native driver defect in a service that other services trust, and it is the
strongest security argument for C over D.

## Performance implications

Option B: poll-mode drivers are fast by design and are the reason DPDK exists.
Option C: a hypervisor and a device passed through cost one exit boundary that a
native driver does not pay. Neither is measurable until something is built, and
this RFC does not claim numbers it does not have.

## Testing plan

Not applicable to a position paper. What a first port under option B would need:
the same gates every driver already faces, plus a hardware boot on the SR550 —
which is the only way to know whether any of this addresses the gap that motivated
it. A driver that passes in QEMU and not on the machine it was written for has
proven nothing.

## Unresolved questions

1. **Which device first?** The X722 is the loudest gap and unblocks hardware
   networking, which nothing else can. The RAID-mode storage controller is the
   other candidate and blocks a disk on the one physical machine.
2. **BSD port or DPDK-style rewrite** for that first device — a straight port
   carries semantics that are known-good; a rewrite carries less code.
3. **When does the hypervisor become real work?** Option C is the endgame and is
   currently unbuildable. It should be a milestone, not a footnote.
4. **Attribution and provenance mechanics** for ported code: SPDX headers, an
   AUTHORS entry, and where the upstream revision is recorded.

## Implementation plan

This RFC lands as a *position*, not as code. If accepted:

1. Record the position in `architecture.md` §8 and the roadmap, replacing
   native-only-by-omission with the tiered answer.
2. Pick the first device under option B, by its own RFC, with counsel consulted on
   provenance before a line is carried.
3. Keep option C as a named milestone with its dependency stated: a hypervisor
   does not exist and is a multi-RFC build.
4. Do not start option D.
