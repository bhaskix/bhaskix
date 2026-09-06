# RFC 0073: speaking LACP, so the switch will listen

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / drivers |
| **Milestone** | Phase 2 — hardware networking |
| **Depends on** | [RFC 0018](0018-networking.md), [RFC 0072](0072-a-driver-for-the-nic-this-machine-has.md) |

---

## Summary

The SR550's four X722 ports are one LACP aggregate. A switch running 802.3ad
keeps a member port *unselected* until the host speaks the protocol, and an
unselected member carries control frames and no data — which is why
[RFC 0072](0072-a-driver-for-the-nic-this-machine-has.md)'s receive queue has
never been handed a frame in eight boots on working hardware.

This proposes **LACP in Bhaskix**: the protocol as pure functions in `net/`,
driven for bring-up by the same path that drives the X722, so that the switch
aggregates a link and data begins to flow. The gate is not "we sent an LACPDU";
it is a DHCP address on VLAN 17.

## Motivation

RFC 0072 built a receive queue that is, as far as eight boots can show,
correct: the device fetches a context this kernel wrote through the host memory
cache, prefetches descriptors from a ring it posted, and reports no error
anywhere. It has never received a frame, and the reason is not in the code.

**The wire has nothing deliverable on it.** Measured across those boots: no
unicast and no broadcast frame has *ever* arrived at the port; the only traffic
is four or five multicast frames a minute at about 150 bytes, which is the size
and cadence of LACPDUs; the VSI counts them and hands them to no queue, because
they go to `01:80:C2:00:00:02`, a reserved address a bridge terminates rather
than forwards. A DHCP `DISCOVER` tagged for VLAN 17 was transmitted, counted out
of the port's MAC, and drew no reply.

The switch port cannot be reconfigured. So either this project speaks LACP or
the only physical machine it has stays without a network — and with it, every
network gate this project has, all of which have only ever run in QEMU.

**What doing nothing costs, precisely.** `docs/roadmap.md` still says of
networking that *"nothing here has run on physical hardware and currently cannot"*.
RFC 0072 removed the driver half of that sentence. This removes the rest, or
nothing does.

## Design

### Where it lives

**The protocol is pure logic and goes in `net/`**, which `forbid`s `unsafe` and
has a budget of zero. That is where RFC 0020 put TCP — *"a pure transition
function"* — and the reasons are the same: a state machine that can be driven
by a host test in microseconds is one that gets tested, and a protocol that
needs hardware to exercise is one that does not.

`net/src/lacp.rs` holds:

* `Pdu` — parse and write an LACPDU, against IEEE 802.3ad's layout.
* `PortState` — the eight state flags, named rather than a bare byte.
* `Actor` — a system id, key, port priority, port number and state; the same
  shape describes us and the partner, because the protocol is symmetric.
* `Machine` — what to believe and what to send next, given what arrived and how
  much time has passed. A pure transition, no clock of its own and no device.

The **driving** — periodic transmission, the device's queues, the port — stays
outside it. For bring-up that is the kernel path that already drives the X722,
as everything in RFC 0072 is; when this moves to a service it is `bin/i40ed`'s
job and no line of `net/src/lacp.rs` changes. That is the point of the split.

### The obstacle before the protocol

**We cannot yet receive an LACPDU, and until we can there is no protocol to
run.** The frames arrive at the port, are counted by the VSI, and reach no
queue. The datasheet's own mechanism for directing an address to a VSI is the
`Add MAC, VLAN Pair` admin command (Table 38-237), whose per-entry flags include
*"Ignore VLAN — if set, the VLAN tag is ignored and the MAC address is used to
forward packets from all VLANs"*.

So step 1 adds `01:80:C2:00:00:02` as a perfect-match filter on this VSI,
ignoring VLAN, and looks. **If that does not work, this RFC stops there** and
the next question is whether firmware's own agent is consuming slow protocols,
which the i40e family answers with a `Stop LLDP`-style admin command. Either
way the answer is one boot away, and no protocol code is worth writing before
it.

### Steps

Each is gated, and the gates are cumulative.

**Step 1 — make one control frame arrive.** `Add MAC, VLAN Pair` for the LACP
group address on the VSI RFC 0072 already found. No protocol code.

> **Gate:** a frame lands in a receive queue and the boot report prints its
> length, EtherType and source. **This also closes RFC 0072 step 4's gate**,
> which is the first time anything has.

**Step 2 — understand it.** `net/src/lacp.rs`'s parser, host-tested against the
standard's field layout and against a real captured LACPDU's bytes.

> **Gate:** the report names the partner's system id, key, port number and
> state flags, read out of a frame the switch sent.

**Step 3 — say something back.** Build an LACPDU advertising this machine —
system id from the port's NVM address, one key for the aggregate, port number
per member — and transmit it on the schedule the partner's timeout flag asks
for.

> **Gate:** the partner's *partner* fields come back naming our system, key and
> port. The switch has not merely received our frame; it has recorded us.

**Step 4 — reach Collecting and Distributing.** The mux machine: when the
partner's view of us matches what we are, set `Synchronization`; when both sides
are in sync, set `Collecting` and `Distributing`.

> **Gate:** the partner's state flags read `Sync | Collecting | Distributing`
> and so do ours, on the same boot.

**Step 5 — data.** With one member selected, the switch forwards.

> **Gate:** the DHCP `DISCOVER` RFC 0072 already builds gets an **OFFER**, and
> the report prints the address. After that, the existing UDP, TCP, IPv6 and
> DHCP gates run on this machine instead of in QEMU.

### One member, not four

This starts with the one port RFC 0072 already drives, and that is a safety
decision as much as a scope one.

A switch with a four-member LACP group and one participating member aggregates
that member and leaves the other three where they already are: unselected,
carrying nothing. **The aggregate currently carries zero traffic**, so a
one-link LAG cannot make the network worse than the state this found it in.
Four members means the kernel claiming all four X722 functions, four sets of
queues and four timers, and it is a later step with nothing to prove that one
member does not.

### Failure behaviour

* **No LACPDU arrives** — step 1's gate fails, and the report says the filter
  was added and nothing came. Nothing else is attempted.
* **A malformed LACPDU** — the parser refuses it and counts it; a partner that
  sends nonsense must not be able to advance our state machine. This is
  untrusted input from the network and gets a fuzz target, as
  `docs/coding-style.md` §8 requires of every parser that touches one.
* **The partner stops** — the state machine expires the partner's information
  after three missed intervals, as the standard says, and falls back to
  `Defaulted`. A link that goes quiet must not stay `Distributing`.
* **The device refuses the filter** — `Add MAC, VLAN Pair` answers `ENOSPC`; the
  report names it and stops.

### `unsafe`

None in `net/`, which forbids it. The driving path's `unsafe` is the existing
kind — writing frames where a device fetches them — and adds no new category.

## What the hardware said, 2026-09-06

Three boots against steps 1 and 3, and the wall moved but did not fall.

**Step 1 — get one LACPDU delivered to a queue — has failed four ways**, each
accepted by firmware and none delivering a frame:

| asked for | answer |
|---|---|
| promiscuous multicast, broadcast and VLAN on the VSI | accepted, nothing arrived |
| `Add MAC, VLAN Pair` for `01:80:C2:00:00:02` | **refused, `EINVAL`** |
| `Add Control Packet Filter` for slow protocols | accepted, nothing arrived |
| `Stop LLDP Agent`, releasing firmware's control port | accepted, nothing arrived |

The `EINVAL` was the useful one: a reserved group address is the bridge's own,
and the datasheet says twice that control flows are routed with the
control-packet filter instead. That correction was made and *lowered* the
`unsafe` budget, the command being direct rather than buffered.

**Step 3 found something better than a gate: the frames never left.**

    nic lacp       45 LACPDU(s) posted with an uplink switch tag, 0 counted out of the MAC; 0 heard back
    nic lacp       the port received 4 packet(s) in those 45 s (4 multicast), against a baseline of about four a minute

Forty-five LACPDUs, and the port's transmit counter did not move once — in the
same boot where an ARP and a tagged DHCP `DISCOVER` were counted out normally,
from the same queue and the same ring. **So the silence that followed says
nothing about the switch. We never spoke.**

The datasheet's explanation was found and acted on, and did not help. A frame
with no switch control tag is *"routed according to hardware filters"*, and the
internal switch consumes one addressed to a reserved group address; reaching
the wire needs the VSI flagged *Allow Destination Override* and a transmit
context descriptor carrying `SWTCH = 01b`, *"uplink packet... transmitted to
the network bypassing hardware filters"*. Both were implemented — the override
by reading the VSI's own configuration, setting one bit and writing it back, so
nothing firmware chose is replaced by a guess — and firmware accepted the
update. **The count stayed at zero.**

### What is left, and one thing that should have been measured first

**An instrumentation gap, stated because it changes which candidate to chase.**
The loop counts LACPDUs *posted*, not *completed*: it waits for each
descriptor's write-back but does not report whether it arrived. So it is not
known whether the device **refused** these descriptors or **took them and the
MAC declined to send**. Those want different fixes and the boot cannot tell
them apart. Reporting completions separately is a two-line change and belongs
before the next hardware experiment rather than after it.

**The leading candidate, once that is known:** a firmware-installed control
packet filter in the *transmit* direction. Table 38-261's flags include
`Direction` — *"0 = apply to Rx traffic, 1 = apply to Tx traffic"* — and a
`Drop filter` bit, so a rule that discards host-originated slow protocols is
expressible, and firmware keeping the host out of its own LACP handling is
exactly the reason to install one. `Remove Control Packet Filter` (`0x025B`)
would clear it. This is a candidate, not a diagnosis: nothing has read back
what filters exist.

**What the eight-boot arc has established**, and it is not nothing: transmit
works for ordinary frames, the receive queue is built and the device runs it,
and the reason no frame arrives is a wire whose data plane is closed. What is
newly known is that the control plane is closed in *both* directions for this
driver, which is a smaller and better-posed problem than "receive is broken".

## Alternatives considered

**Change the switch port.** The cheapest fix by a wide margin: one member
configured outside the aggregate and RFC 0072's queue would receive
immediately. **Rejected because it is not available** — the network's owner has
said the port cannot be changed. It stays recorded as the thing that would make
this RFC unnecessary, and if that ever changes this work is still not wasted:
an OS that cannot join a LAG cannot be deployed on most enterprise racks.

**Static aggregation instead of LACP.** Some switches allow a static LAG with no
protocol. Not available here for the same reason, and it would teach this
project nothing: static aggregation is a switch configuration, not software.

**Speak just enough LACP to be selected, without the state machine.** Send a
plausible LACPDU with `Sync | Collecting | Distributing` always set and never
process what comes back. It might work. **Rejected**: a partner that stops
would leave us claiming to distribute into a link that is gone, which is worse
than no aggregation — it black-holes traffic. The expiry rules are the part of
802.3ad that earns its keep.

**Put LACP in the kernel.** It is a periodic protocol with timers and it would
be easy to bolt onto the existing bring-up path. **Rejected**: `architecture.md`
§2 puts protocol logic outside the nucleus and RFC 0018 already did that for the
whole network stack. The bring-up path drives it during Phase 2 the way it
drives everything else, and that is a scaffold with a known end, not a home.

## Impact on existing design documents

* `docs/roadmap.md` — the networking bullet's *"nothing here has run on physical
  hardware and currently cannot"* is what step 5 changes, and it should not be
  edited before then.
* [RFC 0072](0072-a-driver-for-the-nic-this-machine-has.md) — its step 4 gate is
  met by **this** RFC's step 1, which is an unusual dependency and is stated in
  both places.
* `TRACKER.md` §4 and §7.

## Security implications

**A new parser on untrusted input**, and it is treated as one: `net/` forbids
`unsafe`, the parser refuses malformed frames rather than trusting lengths, and
it gets a fuzz target before merge like every other parser here.

The protocol itself is unauthenticated by design — 802.3ad has no cryptography —
so a station on the same segment can influence which links aggregate. That is a
property of every LACP implementation and of the switch this one talks to, not
something this adds; `docs/security.md`'s threat model already assumes the local
segment is hostile, which is why nothing above the link layer trusts it.

## Performance implications

Two frames a minute at the slow timeout, or two a second at the fast one, of
128 bytes each. Unmeasurable against a 1 Gb/s link, and the state machine runs
once per frame. No budget is proposed because there is nothing here to spend.

## Testing plan

**The protocol is host-tested and the aggregation is not.** `net/src/lacp.rs`
gets unit tests for the layout, the state transitions and the expiry rules, plus
a fuzz target — all on the host, in milliseconds, with no hardware.

What only the SR550 can test is whether a real switch aggregates us, and steps 1
to 5 run there or nowhere. Armed, each of them: a gate that cannot fail has not
been tested, so step 1's must be shown red with the filter not added, and step
4's with `Synchronization` withheld.

## Unresolved questions

1. **Can the device deliver `01:80:C2:00:00:02` to a queue at all?** Step 1
   answers it, and everything after depends on the answer.
2. **Is firmware running its own LACP or LLDP agent** that consumes slow
   protocols before software sees them? If step 1 fails, this is the next
   question, and the i40e family has admin commands to stop such an agent.
3. **What key and system priority does the switch expect?** Read from the
   partner's own LACPDU at step 2 rather than guessed.
4. **Whether one member is enough** for this switch to forward, or whether it
   requires a minimum-links count. Step 5 finds out.
