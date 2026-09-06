# RFC 0074: what a network interface is

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / userspace |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0018](0018-networking.md), [RFC 0029](0029-ipv6.md), [RFC 0073](0073-speaking-lacp-so-the-switch-will-listen.md) |

---

## Summary

This system has a network stack and **no notion of a network interface**.
`bin/netd` drives *the* virtio device, `bin/ipd` reads *the* ring it writes,
and an address belongs to the machine rather than to anything. There is no way
to say "this port", let alone "these four ports bonded", "VLAN 17 on that bond",
or "the address lives on the VLAN".

This proposes the missing concept: an **interface** — a named thing that carries
frames and may hold addresses — in three kinds that compose. A physical port, a
**bond** over several ports, and a **VLAN** on top of either. IP then binds to
an interface instead of to a device.

It is deliberately testable without the one physical machine: QEMU gives a
guest as many virtio NICs as it is asked for, so detection, bonding, failover
and VLANs are all provable on the lanes that already run.

## Motivation

An enterprise server is not plugged into a network the way this stack assumes.
Its ports are trunked, bonded, and carry tagged VLANs, and its address lives on
one of those VLANs rather than on a port. That is the ordinary case, not an
exotic one — it is how the only physical machine this project has is cabled,
and discovering that took eight boots because the system had no vocabulary in
which the question "which interface?" could even be asked.

**Three concrete gaps, each visible in the tree today:**

* **Detection stops at the driver.** The kernel walks ECAM and can name every
  NIC on the bus ([RFC 0072](0072-a-driver-for-the-nic-this-machine-has.md)
  step 1), and nothing above the driver ever learns there is more than one.
  `bin/netd`'s own documentation says *"the machine's virtio network device"*,
  singular.
* **VLAN tags are refused on purpose, and the reason has expired.**
  `net/src/eth.rs` refuses an 802.1Q frame and says why: *"When VLANs are
  supported it will be because something decides which VLAN this interface is
  on."* That refusal was right. This RFC is the something.
* **An address belongs to nothing.** `bin/ipd` holds a slot it calls *"what
  this interface is"* — a page written by the kernel — because there is no
  object to hold it. DHCP therefore runs on "the machine", which cannot be
  right once there are two ports.

**What doing nothing costs.** Every enterprise deployment target in
`docs/roadmap.md` — Phase 3's HA, Phase 5's ecosystem, the first release's
"network clients connect" — assumes an OS that can be given bonded, tagged
links and hold an address on them. Without this the answer to "how do I put
this on our network?" is that you cannot.

## Design

### The model

An **interface** is a named thing that carries frames, has a MAC address and an
MTU, has an operational state, and may hold IP addresses. Three kinds:

| kind | made of | why |
|---|---|---|
| **Physical** | one device port | what a driver presents |
| **Bond** | several member interfaces plus a mode | one logical link over many |
| **VLAN** | a parent interface plus a tag | one link carrying many networks |

They **compose in one direction only**: a VLAN's parent may be a physical port
or a bond; a bond's members must be physical. A VLAN of a VLAN and a bond of
bonds are both refused. That is not a limitation to lift later — stacking
without a rule is how a configuration becomes unreasonable, and the two useful
shapes are `vlan → port` and `vlan → bond → ports`.

### Where the parts live

**The model is pure logic and goes in `net/`**, which forbids `unsafe`: what an
interface is, how a frame is classified to one, how a tag is inserted and
removed, and which member of a bond a frame goes out of. Host-testable, no
device.

**The plumbing stays where it is.** `bin/netd` gains the ability to drive more
than one device and to say what it found; `bin/ipd` binds to an interface. No
kernel object is added — an interface is a userspace concept over capabilities
that already exist, which is the same argument RFC 0018 made for the stack
itself.

### 802.1Q, first class

`net/src/eth.rs` learns to parse a tagged frame into `(tag, inner ethertype,
payload)` and to write one, replacing today's deliberate refusal. **The refusal
is replaced rather than deleted**: an interface with no VLAN configured still
refuses a tagged frame, because accepting traffic from a VLAN it was never
given is exactly the hole the original comment names. What changes is that a
VLAN interface now exists to accept it.

### Bonding, in two modes

**Active-backup first.** One member carries traffic; if its link drops another
takes over. It needs no protocol, no cooperation from the switch, and it is
fully testable in QEMU by downing a link. It is also what a switch that is *not*
configured for aggregation requires.

**LACP second**, using [RFC 0073](0073-speaking-lacp-so-the-switch-will-listen.md)'s
protocol, which is already written and host-tested. A member joins the bond when
its state machine reaches collecting-and-distributing and leaves when it does
not. **What RFC 0073 could not finish is a switch that answers**; the bonding
layer above it does not care, and can be tested against a second Bhaskix guest
or a Linux host long before it meets that switch again.

### Failure behaviour

* **A member's link drops** — the bond selects another; if none is up the bond
  is down and says so. An address on a VLAN above it stays configured, because
  a link that comes back should not need DHCP again.
* **A tagged frame on an untagged interface** — refused and counted, as today.
* **A VLAN whose parent goes away** — the VLAN goes down with it. Interfaces are
  destroyed parent-last.
* **Two interfaces claiming one device** — refused at creation. A port belongs
  to at most one bond.

## Steps

Each is gated, and every gate through step 4 runs on the lanes that already
exist, with QEMU given a second NIC.

**Step 1 — detect and name.** Enumerate every NIC and present it as an
interface with an index, a MAC, an MTU and a link state.

> **Gate:** the boot report lists each NIC as an interface, and a lane given two
> virtio NICs lists two with different addresses.

**Step 2 — 802.1Q in the crate.** Parse and write tags; an interface knows its
VLAN or knows it has none.

> **Gate:** host tests for tag round-trip, for a tagged frame accepted on the
> matching VLAN interface, and for one **refused** on a different VLAN and on an
> untagged interface.

**Step 3 — a VLAN interface with an address.** `bin/ipd` binds to an interface;
DHCP runs on it.

> **Gate:** in QEMU, an address obtained over a tagged interface, and the
> existing UDP and TCP gates passing through it.

**Step 4 — bonding, active-backup.** Two members, one active, failover on link
loss.

> **Gate:** two NICs in a lane; traffic continues across a member being downed,
> and the report names which member is active before and after.

**Step 5 — bonding, LACP.** RFC 0073's machine selects members.

> **Gate:** two Bhaskix guests, or a Linux host, aggregating with this — *not*
> the SR550's switch, whose behaviour RFC 0073 records and which is not a
> dependency of this row.

**Step 6 — the whole shape.** `vlan17 → bond0 → {port0, port1}` with the
address on the VLAN, and the existing network gates running over it.

> **Gate:** the UDP, TCP, IPv6 and DHCP gates pass with the stack sitting on a
> VLAN over a bond rather than on a device.

## Step 4, met 2026-09-07 — a member taken away underneath a bond

**The gate is met.** `make test-bond` boots the two-port machine, reaches in
over QEMU's monitor and takes the first member's link down while the machine is
running:

    net bond       2 member(s), active-backup; traffic on port 0, link up on both
    net bond       failed over 1 time(s): traffic on port 1 now, and 8 frame(s) have crossed since

Before and after, from one boot, which is what the gate asks for. **Watched
red** by making the driver ignore the link register: it then prints `no member
went down inside the window; traffic is still on port 0, link up on 0b11`, and
the harness names that as the failure.

### What had to be built

**The kernel delegates a second NIC**, at slots 10 to 15, with its own rings,
its own IOMMU domain and its own vector. The page table is not shared with the
first port's, and the reason is stronger here than anywhere else in the tree:
the two ports of a bond are on the *same network*, so one translation would let
a frame arriving on the backup land in the buffers of the member carrying
traffic.

**Both vectors raise one notification**, with different badges. A driver that
had to park on two notifications would need a wait that names two sources; it
does not need one, because a wake means "look at both ports" — which is the same
answer this driver already gives for its two queues.

**`bin/netd` drives more than one device**, which is what [RFC
0074](0074-what-a-network-interface-is.md)'s design section said it would have
to. Every window address was welded into a function; they became one `Windows`
parameter, and nothing about *how* a port is driven changed. That is the whole
refactor: the difference between a driver with a device and a driver with ports.

**Link state comes from the device**, not from silence. `VIRTIO_NET_F_STATUS` is
negotiated when offered, and bit 0 of the `u16` six bytes into the device
configuration is the link — both read off `/usr/include/linux/virtio_net.h` on
the machine this was written on rather than remembered. A device that never
offered a link state is treated as **up**: it has not said otherwise, and a bond
that read silence as failure would refuse a working port.

**A failover announces itself.** The member taking over sends the driver's probe
frame immediately. A switch learns which port an address is on from the frames
it sees, and after a failover everything it learned is wrong — Linux's bonding
sends gratuitous ARP here for the same reason. It is also what makes "traffic
continues" a measurement: the answer comes back on the new member and crosses to
`bin/ipd`, so the report can say a frame arrived *after* the failover rather
than that nothing has gone wrong yet.

**Selection is sticky.** A member that comes back does not take the link back:
that is churn and reordering bought for nothing. And a bond whose every member
is down keeps the one it has, because a down member and no member carry the same
traffic, while staying put means a link coming back needs no second decision.

**Frames from a backup member are dropped and counted.** Both members are on the
wire and both receive; a frame taken from the backup would be a duplicate of one
the active member already delivered, and a bond that delivered both would be a
bond that reordered.

### The address survives, and that is the part worth measuring

**Everything the bond sends carries the first member's address**, whichever
member carries it. That is what makes this one interface rather than two:
`bin/ipd` is told an address once and never has to be told again, so a failover
costs no ARP, no DHCP and no reconfiguration above the driver.

It is also the part a failover can quietly break, so it is measured rather than
assumed. The eight frames that crossed after the failover are answers to probes
sent **from the bond's address out of the member that does not own it**, and
they were delivered to that member's queue and handed across. A bond that had
silently become two ports would have shown exactly nothing there.

### What this does not prove

**That this holds on hardware that filters.** Some devices drop a received frame
whose destination is not their own address, and some switches will not accept a
source address that moves; that is what Linux's bonding offers `fail_over_mac`
for, and this has none. What is measured is a virtio-net device model and QEMU's
user-mode network, on which it works.

**And no lane has more than two members.** `MAX_MEMBERS` is eight in the model
and two on the wire, because QEMU gives this lane two NICs.

## Step 5, met 2026-09-06 — two guests, one wire, and a bond that formed

**The gate is met.** `tests/qemu/lacp-test.sh` boots two Bhaskix guests joined
by a socket netdev — QEMU's only netdev that carries raw frames between guests —
and both report the same thing:

    ipd lacp       state 0x3f -- aggregated: synchronised, collecting and distributing

Both sides, because a bond is symmetric: a run where one end says it is
aggregated and the other says nothing answered has found a bug, not half a
pass. The two guests are given **different addresses** in `devices.sh`, and that
is not tidiness — LACP's system id *is* the address, and QEMU gives every guest
the same default, so a pair left on it aggregates with a partner
indistinguishable from itself and proves the arithmetic rather than two systems.

**Watched red.** With `LACP_OPENINGS` set to zero, so neither guest opens the
conversation, both sides print `state 0x07 -- speaking, and nothing has
answered` and the harness fails on each. The assertion distinguishes the two
states rather than matching anything that mentions LACP.

### The first attempt failed, and its two reasons were not the protocol

Recorded here because they were both real, and one of them was a defect in this
system that had nothing to do with aggregation.

**`bin/ipd` never reached its serve loop on a wire with anybody else on it.**
The demonstration phase ends when the ring has been quiet for a long run of
passes — and a *run* is cleared by any frame at all, including frames this
program has no interest in. Two guests kept clearing each other's counter with
ARP and DHCP nobody was going to answer, so neither left the demonstration in
sixty seconds: thirteen million empty passes each, with a longest run of two
hundred thousand, a hundredth of the backstop. **A quiet link is a test
network.** The backstop counts total empty passes now, which is the number that
does not assume one, and the twenty-thousand run still ends a demonstration that
actually finished. This would have bitten on any real network, and it was found
by putting a second machine on the wire.

**The report is a snapshot, and a bond does not form at an instant.** Two
machines have to boot, learn their addresses and exchange LACPDUs; read at a
fixed point the answer is a coin toss, and it was — the same input printed
`speaking, and nothing has answered` once and nothing at all on the next run.
`bhaskix.lacp=<ms>` tells the boot report to *wait* for the bond, which turns
"had it formed by then?" into "did it form within the window?", a question with
the same answer twice. It is set by this one harness and by nothing else,
because every other lane has no partner and would spend the window finding that
out.

The removed harness's third reason stands as well: a QEMU harness must not build
its own device list, and the first one did. This one asks `devices.sh` for a
`paired` profile and tells it a role.

### What this does not prove

That the SR550's switch will aggregate with this. The partner here is another
copy of the same implementation, so a rule both sides read the same wrong way
would still converge. [RFC 0073](0073-speaking-lacp-so-the-switch-will-listen.md)
records what that machine has done so far, and it is not a dependency of this
row.

## Alternatives considered

**Put bonding in the driver.** Each driver aggregates its own ports. **Rejected:**
a bond over two different NICs is the normal enterprise case, and a driver
cannot see another driver's ports. It also duplicates the logic per driver,
which is what `bin/netd` and a future `bin/i40ed` would each have to carry.

**Put interfaces in the kernel.** A capability per interface, created by the
nucleus. **Rejected** by `architecture.md` §2 and by RFC 0018's own precedent:
the stack is outside, and an interface is a *composition* of things the kernel
already hands out. Adding a kernel object would make the nucleus learn what a
VLAN is, which is exactly what RFC 0031 refuses for Linux and this refuses for
the same reason.

**Configuration as a file the shell edits.** Tempting and probably the eventual
surface. **Deferred, not rejected:** the model has to exist before there is
anything to configure, and a format written before the thing it configures is a
format that will be wrong. The standing user-friendliness requirement asks for a
TUI when a configuration surface arises; this RFC creates the surface, and the
tooling is its own change.

**Wait for the SR550's switch.** **Rejected outright.** Eight boots established
that its switch will not answer, and building an OS feature against one
uncooperative switch is how this work drifted in the first place. QEMU gives as
many NICs as are asked for; a second guest can be the far end of a bond.

## Impact on existing design documents

* `net/src/eth.rs` — the VLAN refusal and its comment are replaced, and the
  comment's condition is cited as met.
* [RFC 0018](0018-networking.md) — its two-domain split is unchanged; what
  changes is that `bin/ipd` binds to an interface rather than to the ring.
* [RFC 0073](0073-speaking-lacp-so-the-switch-will-listen.md) — becomes the
  protocol under step 5 rather than a thing pursued for its own sake.
* `docs/roadmap.md` — Phase 2's networking bullet gains this; the enterprise
  rows depend on it.
* `TRACKER.md` §2 and §4.

## Security implications

**A tagged frame must not be believed about which network it came from.** The
whole point of the original refusal: a station on a trunk can send a tag for any
VLAN, so an interface accepts only its own tag and counts the rest. VLAN
membership is a statement about *the switch's* configuration, and this system
treats it as such — it does not become an authorisation boundary here, and
`docs/security.md`'s assumption that the local segment is hostile is unchanged.

Bonding adds no new trust: members are named at configuration time, and a link
that appears is not adopted.

## Performance implications

An interface adds one classification per frame — a tag compare and a table
lookup — on a path that already parses an Ethernet header. Unbudgeted and
expected to be unmeasurable; if it is not, the first number that matters is
frames per second through a bond against through a port, and that comparison is
available from step 4.

## Testing plan

**Steps 1 to 4 and 6 run on the existing lanes** with QEMU given a second NIC,
which costs one line in `tests/qemu/devices.sh`. The model itself — tag
handling, classification, member selection, failover decisions — is host-tested
in `net/`, as every protocol here is.

Armed, each of them: a gate that cannot fail has not been tested. Step 2's
refusal cases must be shown red by accepting a foreign tag on purpose; step 4's
failover by removing the failover and watching traffic stop.

**Step 5 is the only row whose full proof needs something outside**, and the
something is another guest rather than a particular switch.

## Unresolved questions

1. **Where interface configuration comes from at boot.** Hard-coded for the
   gates initially; a real surface is deferred above and is its own change.
2. **Whether `bin/netd` drives several devices or several instances run.** One
   per device is simpler and matches the domain-per-driver argument; one driving
   several shares a ring. Step 1 answers it by having to.
3. **How a bond's MAC is chosen.** Conventionally the first member's. Named here
   so it is decided rather than defaulted.
4. **LACP against a Linux peer** — whether `bonding` in `802.3ad` mode
   interoperates with RFC 0073's implementation is step 5's real test and has
   not been tried.
