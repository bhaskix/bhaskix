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

**For the network that makes it exactly one blocker, which is worth stating
precisely.** RFC 0047 records two independent reasons the SR550 cannot be tested
on the network — no X722 driver, and its IOMMU units off. The second was removed
by RFC 0049 eleven days later and that note went stale; it is corrected there
now. So hardware networking on the only physical machine this project has waits
on a single missing driver, and nothing else.

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

### "Linux is open source -- can we not just read the driver?"

The first question anyone asks, and it deserves a direct answer rather than an
inference from the licence table above. The answer is **yes to writing a native
driver, with care about what is taken from where**, and the line that matters is
**code versus facts**.

**Code is code, and translating it does not change that.** A C driver rewritten
line by line in Rust is a derivative work of the original, and GPL-2.0 travels
with it -- which is the collision [RFC 0001](0001-license-apache-2.0.md) names
when it rejects GPLv2 as *"incompatible with Apache-2.0"*. Transliteration is not
a laundering step, and a reviewer comparing the two files afterwards will see
what happened.

**Hardware facts are not code.** Register offsets, the meaning of each bit, the
order a device must be brought up in, the errata and the "wait for this before
touching that" quirks -- these are facts about silicon, not creative expression,
and a driver written from them is the author's own.

So the practical route, cheapest first:

1. **The vendor datasheet is the clean primary source**, and this project has
   already proved the point. RFC 0043 was recorded as blocked on the VT-d memory
   layout until somebody looked: *"The Intel VT-d Architecture Specification is a
   public document; it was fetched and read, and it answers this directly."* The
   IOMMU work that now runs on the SR550 came from that document. Intel publishes
   equivalent datasheets for the X722 family.

2. **Where a permissively licensed driver exists, port it and skip the argument.**
   FreeBSD drives the same X722 under BSD terms, which permit a direct port into
   an Apache-2.0 tree with attribution. There is no clean-room question, no
   translation question, and no derivative-work question -- the licence already
   grants what is needed. This is option B, and for this specific device it is
   strictly cheaper than reimplementing from the datasheet.

3. **Reading the Linux driver is where the risk concentrates**, because "I read it
   to learn what the hardware needs" and "I transcribed it" are easy to conflate
   and hard to distinguish afterwards, particularly when one person does both. The
   conventional answer is a clean-room split -- one person writes a factual
   specification from the GPL source, another writes the driver from that
   specification alone -- which a single-maintainer project cannot perform
   honestly. **Where option 2 is available, this question does not arise at all,**
   which is the strongest practical argument for preferring BSD sources.

*None of the above is legal advice, and this RFC is not the place that settles it.
Before any code derived from a GPL source is carried here in any form, including
a translation, it needs counsel.*

### What the framework already gives a NIC driver, and what it does not

Checked rather than assumed, because "port a driver" is only cheap if the thing
it ports *into* is ready.

**Already there.** A device in its own ring-3 domain; a DMA window through the
IOMMU (RFC 0049, measured on the SR550); PCIe/ECAM discovery and register blocks
(RFC 0014); interrupt delivery as a capability -- the holder gets `BIND`, `ACK`
and `RELEASE`, and a notification it can wait on. `bin/netd` uses exactly this
surface today: `ATTACH`, `MAP`, `WAIT`, `SIGNAL`, `ACK`.

**Deliberately not there: the driver cannot program its own MSI-X.** `irq.rs`
says so and says why -- *"What the holder gets is `BIND`, `ACK` and `RELEASE`. It
does not get the MSI-X table, and there is no method that would let it program
one"*, because *"a domain that wedges its own device is its own problem; one that
wedges somebody else's is the kernel's"*. The kernel programs the table, through
`Source::MessageSignalled { device, entry }`.

**What that means for a first X722 driver, concretely.** The kernel's source type
already carries an *entry index*, so routing any single MSI-X vector is supported
today. What ring 3 cannot do is ask for a *particular* one, or for several. So:

* **single queue pair, one vector** -- fits the framework as it stands, needs no
  kernel change, and is the right shape for a first driver on real hardware.
* **multi-queue** -- needs the kernel to claim several entries for one device and
  hand each to the driver as its own handler. That is an incremental change to a
  path that already takes an entry index, not a redesign, and it should be its
  own RFC when throughput justifies it.

A first driver should therefore be scoped to one queue pair and judged on whether
it moves a packet on the SR550, not on how fast.

**And it is a bounded amount of code**, which matters because "write a driver"
reads as unbounded. The ring-3 drivers here are all one size:

| driver | device | lines |
|---|---|---|
| `bin/netd` | virtio-net | 1,295 |
| `bin/ahcid` | AHCI/SATA | 1,018 |
| `bin/blkd` | virtio-blk | 951 |

`bin/ahcid` is the comparator that counts: a **real** controller, on real
hardware, written natively, in about a thousand lines of this project's
comment-heavy style. An i40e is a more complicated device than AHCI and a
single-queue driver for it will be larger -- but it is the same order of work,
not a different one, and it is the work that turns the only physical machine this
project owns into a machine with a network.

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
