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

## Step 5, attempted 2026-09-06 — the mechanism is built and the gate is NOT met

`bin/ipd` speaks LACP over the virtio path now: it starts a machine once it
knows its own address, opens with a bounded burst of LACPDUs, answers every one
that arrives, and publishes what the machine believes. All of it passes fmt,
clippy, the host tests and every boot lane.

**What is not proven is that two guests aggregate**, and the reason is the
observation point rather than the protocol.

* **The boot report is a snapshot, and it races.** The kernel reads `bin/ipd`'s
  report page during bring-up; the LACP machine lives in `serve`, which the
  service enters *after* the demonstration. Whether a state established in
  `serve` appears in the report is therefore a race, and it was seen to fall
  both ways across runs — one guest printed `state 0x07 -- speaking, and
  nothing has answered`, and later runs printed nothing at all. **A gate that
  reports differently on identical input is not a gate.**
* **A harness must go through `tests/qemu/devices.sh`.** The two-guest script
  written for this built its own QEMU command line and the invariant checker
  refused it, correctly. It was removed rather than left in the tree.

**What the attempt did establish**, and both are worth keeping:

* **A real defect in `bin/ipd`, unrelated to LACP.** Its configuration was read
  *only* during the demonstration phase. On a link with no gateway that phase
  ends before `bin/netd` has read the device's address, so the service held an
  unspecified address for the life of the boot and could send nothing at all.
  It is read from the serve loop and once more before entering it now.
* **The IOMMU is not optional for any networked lane.** Four two-guest runs
  read as "LACP failed" when the guests simply had no DMA window, so no address
  was ever published. The `net config` line is what said so.

**What would meet the gate**, in the order worth trying: give the report a
later reader, or a second one, so a state reached in `serve` is observable at
all; then build the two-guest harness through `devices.sh` as the rule
requires. The protocol underneath is host-tested against the standard's layout
and its convergence rules, and none of that is in question here — what is
missing is a way to watch two machines do it.

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
