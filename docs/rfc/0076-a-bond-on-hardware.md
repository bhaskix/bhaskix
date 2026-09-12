# RFC 0076: a bond on hardware

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / kernel |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0074](0074-what-a-network-interface-is.md), [RFC 0075](0075-a-driver-that-is-not-in-the-kernel.md) |

---

## Summary

RFC 0074 built bonding and failover, and every claim it makes rests on QEMU and
virtio. This RFC puts a bond over **two X722 ports of the SR550**, and proves
failover by taking the active member's link down through the device's own admin
queue rather than through a hypervisor monitor that does not exist on a real
machine.

## Motivation

**The bond has never met hardware.** RFC 0074 step 4 is met and gated —
`make test-bond` drops a member and watches traffic move — but the member it
drops is a virtio device in QEMU, downed by a QMP `set_link` command. Three
things in that sentence do not exist on a physical machine: virtio, QEMU, and
`set_link`.

That RFC says so itself, in the sentence that has been the honest limit on this
work since the day it was written:

> What is not proven is hardware that filters: a device that drops a frame not
> addressed to itself, or a switch that will not accept a source address moving,
> is what Linux offers `fail_over_mac` for and this has none.

Both of those are properties of *real* devices and *real* switches. A virtio
NIC in a QEMU socket netdev filters nothing and learns nothing. So the two
mechanisms most likely to break a bond on hardware are exactly the two the
existing gate cannot see.

**And the machine is ready for the first time.** Until 2026-09-07 the SR550's
NIC was driven by the kernel and `bin/netd` drove virtio only, so nothing above
the driver could run there at all. RFC 0075 moved the driver into `bin/netd` and
deleted the kernel's copy; the port now transmits and receives from ring 3. What
remains is that `bin/netd` is given *one* port, and a bond needs two.

**All four ports are cabled.** Measured over Redfish on 2026-09-07, with the
host powered off, so the link state is the BMC's NC-SI view rather than the
host's — the boot confirms it from the device:

| | MAC | Link | Speed |
|---|---|---|---|
| NIC1 = `b1:00.0` | `08:94:EF:7A:FC:8E` | LinkUp | 1000 |
| NIC2 = `b1:00.1` | `08:94:EF:7A:FC:8F` | LinkUp | 1000 |
| NIC3 = `b1:00.2` | `08:94:EF:7A:FC:90` | LinkUp | 1000 |
| NIC4 = `b1:00.3` | `08:94:EF:7A:FC:91` | LinkUp | 1000 |

`0x0894ef7afc8e` is the address `bin/netd` put on the interface on the boot
before this was measured, which is what says NIC1 is `b1:00.0` rather than an
assumption about ordering.

## Design

### How many ports, and it is the table that decides

Each X722 port costs one DMA window, four memory objects and **37 register
pages** — 42 capability slots, which is `bhaskix_i40e::grant::SPAN`. The net
domain's first sixteen slots are spoken for, so with `cap::CSPACE_SLOTS` at 256:

| ports | slots | fits 256 |
|---|---|---|
| 2 | 100 | yes |
| 4 | 184 | yes |
| 6 | 268 | no |

**This section said "two, and two is not a preference" until 2026-09-08**, and
against a 128-slot table that was arithmetic rather than opinion: two fit and
three did not. What it got wrong was treating a table size as a property of the
hardware. The SR550's switch bundles all four ports in one channel-group, and
two boots with two members reported `per link: link 0 0x05, link 1 0x05` — both
links heard, neither selected, which is what a four-port channel-group looks
like to a host offering two. The table is 256 now, all four ports are
delegated, and `bhaskix_i40e::grant`'s own test moved with it: it asserts four
fit and **six** do not.

Six, not five — five ports take 226 slots and would fit. The card has four
functions so five is unreachable, but a test asserting a false edge would be
asserting arithmetic nobody had done.

**The other table was already full.** The boot before this change reported
`memory objects 48 of 48 live at once` with two ports delegated: exactly at
`shared::MAX_OBJECTS`, so the next object anything asked for would have been
refused. That was a live fault independent of port count. It is 64 now, and
four ports use 56 of it.

**What was not done, and why.** The 37 register pages dominate the 42, and
`ObjectKind::Memory` already names a set of frames, so collapsing them into
three objects per port is the obvious saving. `REGISTER_PAGES` is **sparse**
across the BAR, and `bin/netd` maps page *P* at `x722_at(n) + P` so every
register offset in `bhaskix-i40e` works unchanged; grouping them would put a
lookup on every register access to save memory the machine has. It would also
blur what RFC 0075 chose deliberately — each granted page named individually,
so anything outside the set faults rather than being reachable, with an exposed
flash and protocol-engine doorbells elsewhere in that BAR.

### The slot layout moves into `bhaskix-i40e`

Today the kernel and `bin/netd` each spell the layout out, and the arithmetic is
duplicated:

```rust
const X722_HMC: usize = X722_PAGES + bhaskix_i40e::REGISTER_PAGES.len();
```

**That duplication has already cost a boot.** RFC 0075 step 4 records the slot
numbers 54, 55 and 56 chosen by hand beside a page range that grew past them.
They are computed now, but computed *twice*, from two files that must agree and
have no way to check that they do. With two ports the arithmetic gains a
multiply and the risk doubles.

So the crate that owns `REGISTER_PAGES` owns the shape of a port's grant:

```rust
/// What one port's grant looks like, as offsets from its base slot.
pub mod grant {
    pub const WINDOW: u64 = 0;
    pub const MEMORY: u64 = 1;
    pub const HMC: u64 = 2;
    pub const RINGS: u64 = 3;
    pub const TX: u64 = 4;
    /// The register pages, last because this is the part that grows.
    pub const PAGES: u64 = 5;
    pub const SPAN: u64 = PAGES + REGISTER_PAGES.len() as u64;
}
```

The pages go **last** for the reason they broke things when they were in the
middle: a variable-length run followed by fixed slots is a range that grows into
its neighbours, and one followed by nothing is not. Both sides then compute
`base(port) = FIRST + port * SPAN` from one definition, and a host test asserts
that two ports fit in `CSPACE_SLOTS` and three do not.

### `X722Registers` gains an address

It is a unit struct with `X722_AT` welded into all three methods. It becomes
`struct X722Registers { at: u64 }`. That is the whole of what stops `bin/netd`
driving two of these — `X722Memory` already carries its own address, and
`bring_up_x722` already takes the device, the admin memory and the VSI as
parameters rather than reading them from constants.

### The bond is the one that already exists

`net/src/interface.rs` holds bonding as pure arithmetic and `bin/netd`'s virtio
path already selects among two ports with it. What does **not** carry over is
`Port`, which holds `Virtqueue<Volatile>` directly and is virtio by
construction. The X722 path is a separate `carry_x722` loop today with no bond
in it at all.

**The bond logic moves, the port type does not.** `carry_x722` becomes a loop
over an array of X722 ports that makes the same three decisions the virtio loop
makes — which member is active, when to change, and which address everything
sends from.

**Those rules are factored out inside `bin/netd`, not called from
`bhaskix-net`.** An earlier draft of this section said the latter and it was
wrong: `tools/check-deps.py` states the rule and the reason, and this program is
the example it names.

> A program linking `bhaskix-net` may hold no *writable* device authority — no
> DMA window, no writable register window, no interrupt. `bhaskix-user-netd`
> fails that and deliberately does not link it.

So the selection is a function in this file that both loops call, which is what
"one set of rules" has to mean here. It is also why the rules are worth
extracting rather than copying: two loops with the same logic written twice
would drift, and the whole claim of step 2 is that the X722 bond behaves as the
virtio bond that is already gated.

Two loops over one set of rules, rather than one loop over two device types
behind a trait: the selection is what must be identical, and it is the part that
is shared.

A trait over both device classes is the tidier design and it is deliberately not
taken here. It would put a virtio refactor on the critical path of a hardware
gate, and RFC 0075's first unresolved question already asks whether `bin/netd`
should hold two device classes at all. If that question is answered by splitting
the service, this trait would be written and then deleted.

### Taking the link down: Restart AN, opcode 0x0605

There is no `set_link` on a real machine. The device has one, and the C620
datasheet §38.11.3.1.3, Table 38-58 gives it — a **direct** command, `Datalen`
zero:

| byte.bit | meaning |
|---|---|
| 16.1 | set to 1 to restart the link |
| 16.2 | set to 1 to **enable** link, 0 to **disable** it |

with the note that says exactly why it is the right instrument:

> Used by the device driver to enable/disable the link without modifying the
> other link settings.

So down is `0b010` and up is `0b110`. **It touches no NVM**, unlike `Set PHY
Config`, so a port cannot be left dark across a power cycle by a boot that
crashes between the two commands — the state is gone at the next PCIe reset.
That property is the reason to prefer this command over configuring the PHY, and
it is worth stating because the alternative is a way to brick a port on someone
else's cluster node.

**This is a real link down.** The PHY stops, so the switch's own port goes down
with it and its MAC table ages out — which is the half of the failure a QEMU
`set_link` on a socket netdev cannot reproduce, and the half RFC 0074 named as
unproven.

### What this does not do

**No LACP.** The bond is active-backup, which needs no cooperation from the
switch and no agreement about what the switch has been configured to expect.
RFC 0073's question — what a real switch does with this implementation's
LACPDUs — stays open and stays deliberately unasked, for the reason it has
always been unasked: it puts a live cluster node into a switch's aggregation.

**No third and fourth port.** The capability space says two.

## Steps

**Step 1 — two ports, driven.** The grant layout moves into `bhaskix-i40e`;
`delegate_x722` takes a port index and is called twice; `X722Registers` gains an
address; `bin/netd` brings both ports up and reports each one's link and station
address.

> **Gate:** an SR550 boot names two X722 ports driven from ring 3, each with its
> own DMA window, and reports a different station address for each — matching
> `…8E` and `…8F` from the table above, which is what says they are two devices
> rather than one counted twice.

**Met 2026-09-07, on the sixth boot.**

    net domain     2 x722 port(s) delegated, each with its own dma window: a bond
                   has two members to select from
    net x722       its LAN queues came up ... it reached step 12
    net x722       port 1 as well: link UP, its LAN queues came up, step 12 --
                   two distinct address(es) between them
    net x722       port 0 0894ef7afc8e, port 1 0894ef7afc8f

The two addresses are the ones the BMC reported for NIC1 and NIC2 before any of
this was written, which is what rules out one device counted twice.

### Four defects, and they are one story

**Every X722 this project has ever driven was physical function 0**, and PF0 is
a special case in which three separately wrong numbers are accidentally right.
None of these could be found in QEMU, which has no X722 at all; none could be
found on one port, either.

**1. The IOMMU built a page table for the first X722 only.** The delegation then
refused port 1 for exactly the right reason — *"registers and no DMA window; not
delegated, because a device that cannot be aimed cannot be driven"* — and the
bug was upstream of that refusal, in a loop that called `find_foreign_nic()`
where it wanted every port it was about to delegate. Each port gets its own
domain id (5 and 7) rather than sharing one: the hardware may share IOTLB
entries within a domain, and two bond members carrying the same address is
precisely where that would let a frame arriving on the backup land in the active
member's buffers.

**2. The queue context was located by the absolute queue index.** `bin/netd`
took a page fault at `0x4411c000` — page 28 of a sixteen-page object — and died
before publishing anything. §38.30.3.4.2 says it three times for the three
places it matters: *"'n' is the queue index within the PF space"* for
`QRX_TAIL[n]` and for `QRX_ENA[n]`, and *"prepare the queue context in the FPM in
the PF memory space"*. Each function has its own BAR (`0x23ffd000000` and
`0x23ffc000000` here), so a register named `Q=0...1535` globally is still
reached PF-relative through that window. On PF0 `FIRSTQ` is zero, so the two
numbers are the same and the error is invisible.

**3. `PFLAN_QALLOC`'s `LASTQ` was used as a queue count.** `queue_allocation`
returned the register's two raw fields and the caller multiplied by the second.
On PF0 that is nearly harmless — `LASTQ` is 383 against a count of 384. On PF1,
which owns 384..=767, a layout sized by 767 wanted **30 backing pages with its
context on page 24** against sixteen granted. Both numbers came off a boot and
both are reproduced exactly by the arithmetic, which is what makes this a
diagnosis rather than a guess. The function returns a **count** now, because two
unlabelled fields are what invited the mistake.

**4. The station address was read from `PRTPM_SAL`/`PRTPM_SAH`, which is the
*WoL* address.** §38.17.3's own source table lists the LAN MAC address as coming
from *"Manage MAC address read"* and lists `PRTPM_SAL/H` under **WoL MAC
Address**. They are equal on port 0 and port 1's `AV` bit is clear, so a port
whose queues had fully come up still reported `000000000000`. The driver asks
firmware now (opcode 0x0107), believes the response's validity bits — an address
firmware has not vouched for is `None`, not zeros — and reads the six bytes as
wire order, because the response says *"all MAC addresses are in big endian
order"*.

### Two pieces of hardening, each of which paid on the next boot

**A layout that will not fit its grant is refused, not written past.** The boot
after that refusal was added is the one where it fired, and `bin/netd` survived
to report both ports instead of dying. `X722Memory` bounds every access and
could not have helped: the context window's *base* is `at.page` pages in, so a
page past the grant is outside the mapping before the first offset is checked.
`grant::HMC_PAGES` is the crate's, so the number the kernel grants and the
number the driver checks cannot drift.

**The report is published after each port, not after both.** Bringing up a
second device is a second chance to die, and the boot where port 1 faulted
published nothing at all — the machine said *"the driver left no report"* and
named neither the port that had come up perfectly nor the one that had not. RFC
0075 step 3 learned this one level out, that a NIC is not required to run but
being able to report is; this is the same rule between two ports.

**What the gate does not yet cover**: `bin/ipd` is still told about one port —
*"0 port(s) published; the service saw 1 port(s)"* — because selecting between
them is step 2.

**Step 2 — a bond over them.** `carry_x722` selects an active member with the
same rules the virtio loop uses — extracted into a function both call, and *not*
`bhaskix-net`, which this program may not link — sends from the bond's address
whichever member carries, and drops a frame arriving on the backup.

> **Gate:** an SR550 boot shows one address on two ports and traffic on the
> active one, and `bin/ipd` is told one interface rather than two.

**Met 2026-09-07.**

    net bond       2 member(s), active-backup; traffic on port 0, link up on both
    net config     interface told to ipd: mac 0x0894ef7afc8e, address 10.0.2.15
    ipd interface  2 port(s) published; the address is on a bond
                   the service saw 2 port(s) and built 2 member(s)

Every boot of this machine before it said *"0 port(s) published; the address is
on a port directly"* and *"saw 1 port(s) and built 0 member(s)"*. `bin/ipd`
builds an interface over a bond now, which is what RFC 0074's model was written
for and had never run outside QEMU.

**One kernel-side fix the gate needed**: `NET_PORTS` counted virtio ports, which
is zero here, so `bin/ipd` was told one port and built no members. Delegated
X722 ports count.

**And the selection rule is one function now**, called by both loops. It gets no
host test -- `bin/netd` is its own workspace, outside `cargo test --workspace`,
which `tools/check-deps.py` states as a rule -- so its gate is `make test-bond`,
the lane that drops a member and watches traffic move. Sharing one
implementation is what extends that lane's reach to the X722 path.

**Step 3 — failover.** `bhaskix-i40e` gains `set_link`, opcode 0x0605, with host
tests. `bhaskix.x722fail=<ms>` downs the active member's link after that long,
and the report shows the bond moving to the backup and traffic continuing.

> **Gate:** one SR550 boot printing traffic on port 0, the link going down,
> traffic on port 1, and the count of frames that crossed after the change. The
> link is restored before the report ends, and the boot after it finds both
> ports up.

**The mechanism works and the gate is NOT met, 2026-09-07.**

    net bond   2 member(s), active-backup; traffic on port 0, link up on both
    net bond   failed over to port 1 and nothing has crossed since:
               36 sent from it, 2 frame(s) had reached the backup before the change

**What is proven.** `set_link` reaches the device and really stops the PHY --
the bond moves only because `Get Link Status` reports the change, so nothing
else could have caused it. Selection picks the backup. **Thirty-six frames left
port 1 carrying port 0's address**, so the X722 does *not* filter egress by
station address, which was one of the three things that could have been wrong.
Port 1's receive path was live throughout. The link is restored and the boot
after finds all four ports up.

**What is not.** Nothing crossed on the new member.

### Two measurement defects found on the way, and both were mine

Each produced a red line that reads like a hardware verdict, which is the
failure this project's rules exist to prevent.

**The bond had no frame of its own.** It forwarded what `bin/ipd` built and
nothing else, so a failover had nothing to be measured by -- the first boot's
"nothing has crossed" was a driver that sent nothing. RFC 0074's note on the
virtio path had already said what was needed: *"a switch learns which port an
address is on from the frames it sees, and after a failover everything it
learned is wrong"*. `fill_announcement` is now shared by both bonds rather than
written twice.

**And the count was taken from the wrong instant.** `report_bond` baselines
frames-handed when *its* window opens; the failover happens earlier, during the
wait for a first frame. A member carrying since the change read as one carrying
nothing. The driver counts from the instant it downed the link and publishes it
in word 26.

### What the numbers now point at, and it is not the driver

Port 1 received **two** frames while it was the backup and **none** in the
roughly three minutes it was active. The switch's own LLDP arrives unsolicited
about every thirty seconds regardless of which member this program has selected,
so an active port that hears nothing while a backup port heard two is not a
quiet wire.

`TRACKER.md`'s **LAG1** row states the likely reason: *"The SR550's four X722
ports are one LACP aggregate."* If those ports are a switch-side port-channel
then **active-backup is the wrong model for this wire** -- a bundle does not
honour an address moving between its own members the way active-backup assumes,
and downing one member can perturb the other. That fits every number here.

**This is a question about the switch, not a defect to fix.** If the ports are
bundled, step 3's gate is asking the wrong thing of this machine and RFC 0073's
LACP path is the right answer for it -- which is a design conclusion rather than
a failure. The gate stays open and says so.

## Impact on existing design documents

RFC 0074's limit sentence — hardware that filters, and a switch that will not
accept a source address moving — is answered or refuted by step 3 rather than
restated. `TRACKER.md`'s **IF1** row records the result either way.

## Security implications

**Authority rises, and by a measured amount.** The net domain goes from 42
capability slots to 84, all of them for a second device of a class it already
drives. Each port keeps **its own DMA window** — not a shared page table, for
the reason RFC 0074 gives for the second virtio NIC: two members of a bond are
on one network, and a shared translation would let a frame arriving on the
backup land in the active member's buffers.

A domain that can disable a link can deny service on that port. It already
could: a domain holding a NIC's registers can stop the device by many routes,
and naming one of them makes it testable rather than making it possible.

## Testing plan

**Host tests** for the grant layout (two ports fit, three do not) and for the
0x0605 encoding (down clears bit 2, up sets it, `Datalen` stays zero), each
watched red.

**Every QEMU lane proves the absence path**, as they did for RFC 0075: no lane
has an X722, so all of this must be inert on all twenty-two.

**And three SR550 boots**, one per step, compared against the boot already
captured. The machine is found powered off and returned powered off, image
unmounted — and for this RFC one thing more: **both ports' links are confirmed
up in the boot after step 3**, because this is the first change in the project
that can leave a network port down behind it.

## Unresolved questions

1. **Whether the switch accepts the address moving.** This is the gate's real
   question and it cannot be answered before it is run. If the switch refuses,
   the answer is `fail_over_mac` — each member using its own address — and that
   is a change to `bhaskix-net`'s bonding, not to this delegation.
2. **Which switch ports these four land on.** The driver receives LLDP already;
   step 1 can report the neighbour it hears on each port, which would say
   whether the two members share a switch. It is reported rather than acted on.

## A bug this work found in the kernel, which predates it

**The kernel polled a service's report page through a plain slice.** Both waits
that watch another domain change something -- the net report's failover wait and
the LACP aggregation wait -- read the page as a `&[u8]` and re-read it each
pass. Nothing in that tells the compiler the page has another writer, because
the writer is a domain it cannot see, so the loads are hoistable clean out of
the loop: the wait then examines **one snapshot** until it gives up.

Both loops carried a comment saying the opposite. The net one said *"Read again
rather than once: the driver writes this page while it is read"*; the LACP one
said *"`bin/ipd` writes this page while it is read"*. The intent was written
down. The guarantee was not in the code, and no test could see the difference.

**It has always been there and passed by luck of codegen.** Widening the net
report from 24 words to 28 changed the optimiser's mind and `make test-bond`
began failing every run. Six explanations were tried and all six were wrong --
host load, a global substitution hitting other arrays, stack pressure, the
`carried` rule, the added print blocks, and the belief that reading unused words
cannot matter. What settled it in one run was printing what the kernel actually
read: `w17..21 = 2 0 3 0 0`, the state *before* the link went down, held
constant while `bin/netd` had long since moved to port 1. Not garbage, not a
wrong address -- stale.

Each word is read with `read_volatile` now. **The kernel's unsafe count fell**,
2019 to 2017, because the volatile reads replaced more lines than they added.

**The LACP one matters beyond the lane.** It is the wait this RFC's own step 3
leans on, so every "the switch never answered" result recorded above rests on a
wait that may not have been able to observe an answer. The counters added
alongside -- LACPDUs sent and slow-protocol frames heard -- are what will settle
that, and they did not exist when those boots were taken.

## One state machine per link, which is what 802.3ad says

The switch config arrived from the project lead partway through this work:
*"sr550 have 4 nic on switch 4 port LACP with TRUNK and vlan tagged
17,5,20,10,2,3,50."* That answered unresolved question 1 before the gate could:
the ports are a channel-group, so active-backup is the wrong model for this wire
and the address never had a chance to move. It also explained every quiet boot
in this document — a trunk drops untagged data, and every frame this stack had
ever built was untagged.

So the stack became a bond on 802.3ad, a VLAN 17 interface over it, and DHCP on
that, in that order. LACP then worked in both directions and the report could
say so: **11 sent, 3 heard**, with the machine's own state at `0x05` — ACTIVITY
and AGGREGATION, and no SYNC. A partner heard from, and no bundle.

**`0x05` was this service's own fault, not the switch's.** `bin/ipd` ran *one*
`lacp::Machine` with `Actor_Port = 1` and duplicated its PDU onto every member
of the bond. A switch shown two links that both claim port 1 of one system has
no aggregation it can form: the frames describe a single port that cannot be on
two cables, so it answers each and synchronises neither. The duplication was
added one step earlier for a reason that was half right — a bundle forms only if
every link speaks — and got the other half exactly backwards.

The shape now:

* **`bin/ipd` runs one machine per member**, each with `Actor_Port = index + 1`
  and a partner of its own, sharing one key because the key is what says these
  links may aggregate together. A PDU arriving on a link is answered by that
  link's machine; routing them all to one machine would let the second link's
  partner overwrite the first's, and the report would show a bundle neither had.
* **The length prefix carries the member**, four bits at bit 24, stored as
  index + 1 so that zero keeps its meaning of *whichever member carries
  traffic*. `bin/netd` reads an index and never the frame, which is RFC 0018's
  rule for the domain holding DMA. It replaced a broadcast bit, and the encoding
  is tested on the host in `bhaskix-abi`.
* **`bin/netd` stamps the member a frame arrived on**, so an answer goes back
  down the link the question came in on.
* **In an aggregation every member's frames go up.** Active-backup drops the
  backup's as duplicates; a bundle has no duplicate to drop, and a bond that
  dropped them would never hear the second link's partner at all. The mode
  reaches the driver as a word the kernel writes into the report page before the
  driver starts — a configuration fact, not a fact about any frame.
* **The report states what every machine agrees on**, not one machine's view: a
  bundle is up when each link is synchronised, so SYNC shown because one of two
  links had it would claim an aggregation that does not exist.

**The honest limit, which the boot cannot hide.** This kernel delegates two of
the four X722 ports, because a domain's capability space bounds how many it can
hold. The switch's channel-group has four. Whether a switch will bundle two
links of a four-port group depends on its configuration, and if it will not,
per-member machines are still the right shape and still will not aggregate —
the next step is then more ports, not a different state machine.

### What the machine said, 2026-09-08

Booted with `bhaskix.bondlacp bhaskix.vlan=17 bhaskix.lacp=90000 bhaskix.x722=120000`,
both X722 ports delegated with their own IOMMU domain, LAN queues up from ring 3
to step 12. Against the boot before it:

| | one machine | per-member machines |
|---|---|---|
| `net ring` | **FAILED: 0 frames crossed** | **4 crossed, 590 bytes, 0 refused** |
| LACPDUs | 11 sent, 3 heard | 21 sent, 5 heard |
| LACP state | `0x05` | `0x05` |
| `net domain` | FAILED: nothing was transmitted | FAILED: nothing was transmitted |
| `dhcp client` | FAILED | FAILED |

**A gate turned green: frames now cross from `bin/netd` to `bin/ipd` on this
machine**, and the first one came from `08:bd:43:76:47:e3` — the switch. LACP
traffic roughly doubled, which is two machines speaking where there was one.

**The aggregation did not form, and this boot cannot say why.** That is a defect
in the instrumentation and it was mine: `lacp_publish` published the bitwise AND
of every machine's flags. The AND is the right rule for the verdict and the
wrong thing to record — `0x05` means *either* "neither link synchronised" *or*
"one did and one did not", and a boot cannot be re-read to find out which. On a
wire where the switch bundles four ports and this kernel drives two, those are
completely different findings.

So each machine's flags now go in their own byte of the published word, machine
`n` at bit `8n`, with zero meaning *no machine* — a running one always has
ACTIVITY set. The kernel derives the verdict from every link and prints a
`per link:` line naming each. Machine 0 keeps the low byte, so a reader of the
old shape still reads a true thing. **The next boot will answer the question
this one could not**, and until then the honest statement is that the bundle did
not come up and the reason is unmeasured.

Two red lines are older than this work and stay flagged rather than fixed:
`net domain FAILED: nothing was transmitted`, which sits beside `41 sent back`
in the same report and so is a measurement question before it is a device one;
and DHCP, which cannot be answered while the bond is unbundled — a switch does
not forward data to a member it has not selected.

**One operational note, because it cost an hour.** Redfish virtual media on this
BMC returns HTTP 500 on every slot — `EXT1`–`EXT4`, `Remote1`–`Remote4`, and
Lenovo's own `RemoteMap` action — after fetching the image successfully, and a
BMC restart does not clear it. What works is the XCC's own CLI:
`rdmount -map -t http -ro -l <url>` then `rdmount -mount`, with `rdmount -umount`
to release it.

### The per-link report answered it, and corrected the boot before

Booted again the same day with the per-link reporting in place:

```
ipd lacp       23 LACPDU(s) sent, 7 slow-protocol frame(s) heard back
ipd lacp       state 0x05 -- a partner is heard but the link is not yet aggregated
               per link: link 0 0x05, link 1 0x05
               the partner's key is 20
```

**Both links, not one.** The AND was hiding nothing: the switch synchronises
neither member. That closes the question the previous boot could not answer and
rules out the reading where one link had come up and the report could not say
so. What remains is a switch that hears both links, answers both, gives its key
as 20, and selects neither -- which is what a channel-group configured for four
members looks like to a host offering two.

**And a correction to the section above, which claimed too much.** It read
"a gate turned green: frames now cross", from a boot whose `net ring` line said
`4 crossed`. This boot's said `0 frames crossed` and `FAILED`, with
`net after 1 completions seen, 2 handed across` in the same report -- so frames
*did* cross and `bin/ipd`'s report page was simply read before it had taken
them. The line is a sample, not a verdict, and the switch's unsolicited LLDP
arrives about every thirty seconds, so whether the sample catches one is timing.

The defensible claim is narrower and still worth having: **frames cross from
`bin/netd` to `bin/ipd` on this machine** -- `handed across` is non-zero on both
boots, and the first frame's source on the boot that caught one was
`08:bd:43:76:47:e3`, the switch itself. The `net ring` *gate* is timing-sensitive
and has been red and green on consecutive boots of the same image; treating one
green sample as a gate that turned is exactly the error this document keeps
having to correct.

### Four ports on the machine, 2026-09-08

```
iommu window   b1:00.0 … x722 port 0's own page table and domain 8,  2 in use
iommu window   b1:00.1 … x722 port 1's own page table and domain 9,  3 in use
iommu window   b1:00.2 … x722 port 2's own page table and domain 10, 4 in use
iommu window   b1:00.3 … x722 port 3's own page table and domain 11, 5 in use
net domain     4 x722 port(s) delegated, each with its own dma window
net bond       4 member(s), 802.3ad; traffic on port 0, link up on ports 0, 1 only
ipd interface  4 port(s) published; the address is on an 802.3ad bond
ipd lacp       44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
ipd lacp       state 0x05 -- a partner is heard but the link is not yet aggregated
               per link: link 0 0x05, link 1 0x05, link 2 0x05, link 3 0x05
               the partner's key is 20
memory objects 56 of 64 live at once
fixed tables   … cspace 256 slots … 365 KiB of static kernel memory
```

Both raised tables land where the arithmetic said: 56 of 64 objects, and fixed
tables at 365 KiB against 269 before. LACPDUs went 23 to 44 and slow-protocol
frames heard 7 to 12, so all four machines speak and all four are answered.

**The first attempt panicked the kernel**, and it is worth writing down because
the shape of the mistake is familiar. `KERNEL PANIC: index out of bounds: the
len is 2 but the index is 2` — `X722_MEMBERS` went to four and the IOMMU loop
still read `let domain = [5u16, 7][nth as usize]`, a written-out pair whose own
comment said the ids were spelled out "so that a collision is visible here
rather than arithmetic somewhere else". Writing a number out does not make it
agree with a count. It is a run now, `X722_FIRST_DOMAIN + nth`, with a
`const _: () = assert!(…)` against `iommu::PASS_THROUGH_DOMAIN`, so the next
raise fails at build time instead of on a server. **No QEMU lane has an X722**,
so no lane could have caught it — the same reason the four PF0 driver defects in
this RFC reached hardware first.

**Two findings this boot opened.**

~~**Ports 2 and 3 report link down to the driver and LinkUp to the BMC.**~~
**Wrong, and the defect was mine.** The bond line said `link up on ports 0, 1
only` while Redfish reported all four NICs `LinkStatus: LinkUp, SpeedMbps:
1000`, and that was read here as a question about `Get Link Status` on
functions 2 and 3. It was not. `carry_x722` polls every member's link -- that
loop is `members.iter_mut().flatten()` and always was -- but the array handed to
`select`, and used to build the report's link bitmap, was written out by index:

```rust
let up = [members[0]…is_some_and(|m| m.up), members[1]…is_some_and(|m| m.up)];
let links = u64::from(up[0]) | u64::from(up[1]) << 1;
```

Two entries, correct while a bond was two ports, left behind when
`X722_MEMBERS` became four. Members 2 and 3 were polled and then **never
consulted**: `select` could not choose them and their bits were structurally
zero. The ports were not reporting down; nothing was asking.

Both are built from `X722_MEMBERS` now, and the bitmap folds over the same
array `select` reads so the report cannot disagree with the choice.

**This is the second time in one change that a written-out pair outlived the
count beside it** -- the first panicked the kernel on `[5u16, 7][nth]`. The
lesson the kernel one already carried is the lesson here: an array whose length
must equal a constant should be built from that constant, and a sweep for the
pattern is worth more than a fix for the instance.

**What the generalised link naming did earn**: the old two-member code was a
chain of `if`s whose last arm was an `else`, so it would have printed "both"
for this bitmap and shown nothing amiss at all. The wrong answer was visible
only because the naming had been fixed first.

**Confirmed on the machine, same day**, with both arrays built from
`X722_MEMBERS`:

```
net bond       4 member(s), 802.3ad; traffic on port 0, link up on every one of them
ipd lacp       47 LACPDU(s) sent, 15 slow-protocol frame(s) heard back
ipd lacp       state 0x05 -- a partner is heard but the link is not yet aggregated
               per link: link 0 0x05, link 1 0x05, link 2 0x05, link 3 0x05
```

All four links up, which is what the BMC had been saying all along, and frames
handed across went 1 to 7. **The aggregation question is unchanged**: four live
members, all four speaking, all four answered, none selected. That was true
with two members and is true with four, so the number of members was never the
variable — which is worth knowing, because it was the last thing this side
could vary.

**Aggregation did not form on any of the four links.** All four sit at `0x05`
with partner key 20. Offering the switch every member of its channel-group did
not change its answer, which exhausts what this side can vary: the remaining
question is the switch's own configuration — whether that group is LACP
*active*, and what it expects of a peer. RFC 0073's premise, that speaking the
protocol correctly is sufficient, is not confirmed by this machine.

### Reading the switch off its own PDUs, 2026-09-08

The host has no login on the switch. It does not need one: **every LACPDU the
switch sends carries its own state flags and its record of whoever it believes
is at the far end**, and this service was parsing both and discarding them.
`Machine` keeps the second now (`recorded`, host-tested and watched red), and
`bin/ipd` publishes the partner's flags per link beside its own.

```
ipd lacp   44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
ipd lacp   state 0x05 -- a partner is heard but the link is not yet aggregated
           the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
           so the switch is LACP active
           and records its partner as key 0, port 0 -- ours are key 1, port 1
```

`0x45` is **ACTIVITY | AGGREGATION | DEFAULTED**, identically on all four links.

* **ACTIVITY** — the switch is configured *active*, not passive. It speaks
  first, so the reading this RFC has carried since `Machine::new` ("one of the
  two readings of why the SR550's wire looks silent") is settled: not that one.
* **AGGREGATION** — it treats each port as aggregatable, not individual.
* **DEFAULTED** — *the partner's information is made up rather than received.*

**That third flag moves the fault.** The switch is not misconfigured and is not
refusing this host: it has never received a usable LACPDU from us, so it runs on
administrative defaults for its partner — which is exactly the partner record it
advertises, key 0 and port 0. Forty-four PDUs leave this side by our own count
and the switch's own flags say none arrived.

So the open question is no longer the switch's configuration. It is **what
happens to an LACPDU between `bin/ipd` building it and the wire**: whether the
X722 transmits those frames at all, and whether what arrives is well formed.
That is answerable from this side, which the previous question was not.

**Two defects of mine on the way to this, both about zero.**

The first measurement was not a measurement. `write_report` took a `[u64; 32]`
while the kernel had grown to read 34, so the two words carrying this finding
were **never written**, and unwritten page memory is zero -- a legitimate value
for both. The report then stated, in a sentence, that the switch recorded no
partner. It was reading memory nobody had assigned, and it took two hardware
boots to notice because the conclusion was plausible.

The second was the same error one level down: the partner's flag byte was
published without a *heard* bit, so `0x00` -- passive, individual,
unsynchronised, a perfectly legitimate advertisement -- was indistinguishable
from silence.

Both are structural now rather than remembered. The report length is one named
constant, so the array and the signature cannot drift without the compiler
saying so; `bin/ipd` writes a sentinel one word past its report, and the kernel
refuses to interpret anything past what that sentinel proves was written,
saying `ipd report INCOMPLETE` instead. **Watched both ways on real boots**:
red with the tail write removed, green with it restored -- after two earlier
checks that proved nothing, because a lane prints only its verdict on success
and the logs I grepped never contained the report at all.

### Where the LACPDUs went, 2026-09-09

The switch said DEFAULTED: it had never received a usable LACPDU. This side
counted 44 sent. Both were true, and the frames died in between — inside the
X722 itself.

**The device carries an internal switch, and a transmit descriptor with no
switch control tag is *"routed according to hardware filters"*.** A frame
addressed to `01:80:C2:00:00:02` — a reserved group address — is therefore
consumed by that switch rather than put on the wire. Two things lift it out,
and the crate has had both since 2026-09-06:

* `SWTCH = 01b` in a transmit **context** descriptor: *"uplink packet. The
  packet is transmitted to the network bypassing hardware filters."*
* The VSI's *Allow Destination Override* flag, without which a switch control
  tag is **not permitted at all** — C620: *"Can be set to non-zero only by
  control VSI as programmed by the Allow Destination Override flag per VSI."*

**Neither was ever wired into `bin/netd`.** `post_frame`'s `uplink` argument was
passed `false` at both call sites, and `allow_destination_override` had no
caller outside the crate's own tests. The reasoning was written out in full at
`TX_SWTCH_UPLINK`, naming the exact symptom — *"posted and completed and never
counted out of the MAC"* — and then the mechanism sat unused for three days
while four hardware boots looked for the fault somewhere else.

**A mechanism nobody calls is not a mechanism.** The lesson is not about this
register: a constant with a careful doc comment reads exactly like working code
in every grep, every review and every recollection, and the only thing that
distinguishes them is a caller. `grep` for the definition finds it; what was
needed was a grep for the *use*.

It also explains the shape of the evidence, which had been consistent all along
and pointed inward rather than at the switch:

| observation | explanation |
|---|---|
| `bin/ipd`: 44 LACPDUs sent | it handed 44 to the driver |
| `bin/netd`: posted, descriptors completed | the device accepted all 44 |
| switch: DEFAULTED, partner key 0 port 0 | none reached the wire |
| the switch's own LLDP arrives here | receive is unaffected by any of this |
| all four links identical | it is the device, not a cable or a port |

**What the fix is.** `bin/netd` calls `allow_destination_override` during
bring-up, and posts a frame with the uplink tag when `bin/ipd` asks for it.
Which frames ask is `bin/ipd`'s to say and not the driver's: RFC 0018 keeps the
frame opaque to the domain holding DMA, so the driver cannot tell an LACPDU from
a datagram. It travels as **bit 28 of the ring's length prefix**, beside the
member index — `ring::UPLINK`, host-tested and watched red, with the test
asserting that neither the length nor the member can forge it.

### The frames do leave, and the counter is how we know — 2026-09-10

```
net x722   34 multicast frame(s) left the vsi by its own count; destination override taken
net bond   4 member(s), 802.3ad; traffic on port 0, link up on every one of them
ipd lacp   44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
ipd lacp   state 0x05 -- a partner is heard but the link is not yet aggregated
           the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
           so the switch is LACP active
           and records its partner as key 0, port 0 -- ours are key 1, port 1
```

**Both halves of the uplink fix took.** `allow_destination_override` was accepted
and the VSI's own multicast transmit counter moved. The internal switch is no
longer eating the frames.

**And the first report of this change was wrong.** The boot immediately after the
fix said `0x45` exactly as before, and it was written up here as "the fix did not
change the outcome". It had changed the outcome; what had not changed was the
*switch's answer*, and nothing in the system could tell those apart. `GLV_MPTCL`
counts multicast packets the VSI put out, and until this build it was not mapped
— so every figure in the report counted frames **handed over** and none counted
frames **transmitted**. Three days of boots turned on a distinction no instrument
could make.

That is the same error as the report-page words and the partner's flag byte, in
its third form: a quantity that was never measured, read as a measurement of
zero. The register addresses here were taken out of the C620 datasheet rather
than recalled — `GLV_MPTCL[n]` at `0x0033CC00 + 8n`, *"Counts number of multicast
packets transmitted by this VSI"* — and cost three register pages, so
`grant::SPAN` is 45 and four ports take 196 of 256 capability slots.

**What is ruled out now**: the internal switch consuming the frames, the
destination override being refused, and the transmit path being dead. **What
remains**: a switch that is LACP *active*, hears nothing usable from us, and runs
on made-up partner information — key 0, port 0.

### The next hypothesis, stated as a hypothesis

**Every LACPDU on all four links carries the same Ethernet source address.**
`bin/ipd` is told exactly one MAC on its configuration page and uses it — port
0's — for all four machines. That the LACP *system id* is shared is correct and
required by 802.3ad; that the *Ethernet source* is shared is not. Four ports of
one channel-group all sourcing from one address is a MAC-flap signature, and a
switch may drop such frames before its LACP ever sees them.

This is a **code fact that was checked, not a measurement of the switch.** It
fits the evidence — all four links identical, frames leaving, nothing arriving —
and it is the first thing to try. Testing it means carrying every member's
address on the configuration page so each machine sources from its own port,
which is a change to that interface rather than a one-line fix.

### Every link under its own address — 2026-09-10

The hypothesis above is now built. What it took was not a one-line fix, because
the address a link is called by had nowhere to travel: `bin/netd` published one
address, the kernel passed on one address, and `bin/ipd` had one address to put
on four frames. Three interfaces widened, in the same shape each time — a block
of member addresses, and a sentinel saying the block has been filled in.

**`bin/netd`, `ring::MEMBER_ADDRESSES`.** Word 32 of the report page is a
sentinel and four addresses follow it, one per member, zero where there is no
member. Every X722 port already read its own address off firmware and threw
three of them away; every virtio port already had its device-configuration
window mapped, and the comment beside the second one said in as many words that
its address *was read by nobody*. Both are read now.

**The sentinel is not decoration.** That driver publishes its report after each
port it brings up — deliberately, so a port that faults does not take the
previous port's findings with it — so the marker appears one port in. The kernel
reads the configuration the moment the marker appears. Without a sentinel it
would have read three addresses that had not been asked for yet, published them
as zeros, and `bin/ipd` could not have told those from three members that have no
address. That is the same defect as the report-page words, the partner's flag
byte and `GLV_MPTCL`, in its **fourth** form, and this time it was designed
against rather than discovered.

**The kernel, configuration words 7 to 10.** One address per member, appended by
length rather than written out — this file has twice recorded a written-out pair
outliving the count beside it, and the bond's link bitmap is one of them.

**`bin/ipd`, `Bundle::source`.** Each machine's Ethernet header now carries its
own member's address. The LACP **system id** is untouched and shared, which
802.3ad requires: the system id is what says these links may aggregate together,
and four links advertising four system ids would be four aggregations of one.
What changed is a different field with a different rule.

A member with no address of its own falls back to the bond's, which is where
this service was before — worse than the port's, better than a frame with no
source at all. The source is refreshed on every pass rather than fixed when the
machine is created, because a member's address arrives when its port comes up
and that can be after this service has started speaking for it.

**What the boot says now**, from the `test-bond` lane, which has two virtio ports
with distinct addresses and is the first lane able to see any of this:

```
net config   interface told to ipd: mac 0x525400123456, address 10.0.2.15
net config   each link speaks under its own address: port 0 0x525400123456, port 1 0x525400123457
ipd lacp     state 0x07 -- speaking, and nothing has answered
             speaking as: port 0 0x525400123456, port 1 0x525400123457
```

Two lines, because they answer different questions. The first is what the kernel
*published*; the second is what `bin/ipd` *did with it*, read back off its own
report at words 34 to 37. A boot that shows four identical addresses on the
second line has found the bug rather than hidden it, and `tests/qemu/bond-test.sh`
fails on exactly that.

### What this does not claim

**The switch has not been asked yet.** This is a conformance fix with a
hypothesis attached, and the two should not be confused:

* That an LACPDU's source is the individual address of the port it leaves by is
  **recalled from 802.1AX §6.4.4 and not verified against a copy of the standard
  on this machine.** The project's rule is to say so rather than assert a
  specification from memory. It is also the only reading under which a
  per-port `Actor_Port` makes sense, which is weak evidence and is offered as
  such.
* **The MAC-flap reasoning is weaker than it was written.** Linux's bonding
  driver puts the *bond's* address on every slave in 802.3ad mode by default, so
  if one address across four links were on its own fatal to LACP, Linux would
  not aggregate either — and it plainly does. That argument is recorded here
  because it was the one that motivated the work, and it should not be quoted
  later as though it survived.

So what is now true is narrower and worth stating plainly: **the frames are
correct in a way they were not before, and whether the switch cares is the next
boot's question.** If `DEFAULTED` clears, the hypothesis was right. If it does
not, the remaining suspects are what the switch's channel-group is configured to
expect and whether the VLAN tag on an uplink-tagged frame is what that
configuration will accept — neither of which this host can read off the wire.


### The switch was asked, and said no — 2026-09-10

The boot happened. Same command line as the one before it, so the two are
comparable: `bhaskix.bondlacp bhaskix.vlan=17 bhaskix.lacp=90000
bhaskix.x722=120000`.

```
net config   each link speaks under its own address:
             port 0 0x0894ef7afc8e, port 1 0x0894ef7afc8f,
             port 2 0x0894ef7afc90, port 3 0x0894ef7afc91
net x722     38 multicast frame(s) left the vsi by its own count; destination override taken
net bond     4 member(s), 802.3ad; traffic on port 0, link up on every one of them
ipd lacp     44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
ipd lacp     state 0x05 -- a partner is heard but the link is not yet aggregated
             per link: link 0 0x05, link 1 0x05, link 2 0x05, link 3 0x05
             speaking as: port 0 0x0894ef7afc8e, port 1 0x0894ef7afc8f,
                          port 2 0x0894ef7afc90, port 3 0x0894ef7afc91
             the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
             so the switch is LACP active
             and records its partner as key 0, port 0 -- ours are key 1, port 1
```

**The change works and the hypothesis is dead.** Four links speak under four
addresses, the card's own port MACs, carried the whole way from firmware through
`bin/netd`'s report and the kernel's configuration page into `bin/ipd`'s Ethernet
headers. And the switch's answer did not move by one bit: `0x45` on all four
links, `DEFAULTED` still set, partner still recorded as key 0, port 0.

So the section above stands as written, including the part that said the
MAC-flap reasoning was the weaker half. It was the weaker half. **A shared source
address is not what is keeping this switch from aggregating**, and the fix that
came out of that reasoning is worth keeping on conformance grounds alone —
which is the only claim that survives.

**The other suspect named above is also ruled out, from the code rather than by
guessing.** `bin/ipd`'s `frame` writes a plain untagged Ethernet header, so the
LACPDUs go out untagged despite `bhaskix.vlan=17`. That is what the standard
asks for — a slow protocol is a link talking about itself, not traffic on a
VLAN — and it means the tag cannot be what the switch is refusing.

**What this boot also confirmed**, none of it the subject and all of it worth
having: the widened report is written in full, with no `ipd report INCOMPLETE`,
so the sentinel survives a report that grew by four words; `4 x722 port(s)
delegated` with domains 8 to 11; `56 of 64` memory objects and `365 KiB` of fixed
tables, both tables landing where the arithmetic said.

### What is left, and the instrument it needs

**A gap that has been in every one of these reports and was not read until now**:
44 LACPDUs sent, **38** multicast frames out of the VSI. The boot before it was
44 and 34. Six frames are unaccounted for in both, and nothing here says where.

`GLV_MPTCL` counts what the **VSI** put out. There is a port-level counter,
`GLPRT_MPTC`, that counts what the **MAC** put out, and it is not mapped. That
pair is the one measurement that would separate the two remaining stories — a
frame that left the internal switch and reached the wire, against one that left
the internal switch and died before the MAC — and it is exactly the shape of
question `GLV_MPTCL` itself was added to answer one step earlier.

Until that is measured, the honest position is that **the transmit path is proven
as far as the VSI and no further**, and every conclusion about what the switch
did or did not receive rests on that boundary.


### The frames reach the wire — 2026-09-10, third boot

`GLPRT_MPTCL` is mapped, and it answers.

```
net x722   38 multicast frame(s) left the vsi by its own count; destination override taken
net x722   38 of them reached the mac by the port's own count -- the wire is where they went
ipd lacp   44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
ipd lacp   state 0x05 -- a partner is heard but the link is not yet aggregated
           the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
           so the switch is LACP active
           and records its partner as key 0, port 0 -- ours are key 1, port 1
```

**Thirty-eight out of the VSI, thirty-eight out of the MAC.** Nothing is lost
inside the device between those two boundaries. The section above said the
transmit path was *"proven as far as the VSI and no further"*; it is now proven
as far as the MAC, which is the last boundary this host owns.

So the position has changed, and it is worth stating precisely because it is the
first time in this work that it can be: **everything measurable on this side says
the LACPDUs go out onto the wire, and the switch says it has never received a
usable one.** Those are no longer reconcilable by anything inside this machine.

**The counters were already in the crate and nothing read them.**
`GLPRT_UPTCL`, `GLPRT_MPTCL` and `GLPRT_BPTCL` have been declared in
`bhaskix-i40e` since 2026-09-06, each with its datasheet section quoted beside
it, and no caller. That is the same shape as `TX_SWTCH_UPLINK`, which cost three
days one step earlier, and it means the measurement that moved this question was
available the whole time. `Device::port_counters` — the receive half — still has
no caller today.

**The datasheet contradicts itself here, and the reading is recorded rather than
assumed.** §38.39.2.16.62 is headed *"Port Multicast Packets Transmit Count Low
- GLPRT_MPTCL[n]"* with `n=0...3`, while its field description says *"Counts
number of multicast packets transmitted by this VSI"* — word for word
`GLV_MPTCL`'s, evidently copied. Table 38-369 gives the prefixes (`GLPRT` = port,
4 instances; `GLV` = VSI, 384) and §38.28.4.1 puts the `GLPRT` set under *"MAC or
Physical Uplink Interface Statistics"*. Three things say port and one says VSI,
so it is read as a port counter — and the host test asserts the two sets return
different numbers, watched red by making the reader use the VSI offsets, which
is exactly the bug the description invites.

**What the remaining gap is not.** 44 LACPDUs sent against 38 transmitted is not
a loss inside the device: the VSI and the MAC agree, so whatever the difference
is, it is not frames dying between those two boundaries.

> **Corrected 2026-09-10.** This paragraph went on to say the six frames *“never
> reached the VSI at all”* and named `bin/ipd`'s ring and `bin/netd`'s posting as
> where to look. That was a subtraction across two clocks, and the section at the
> end of this document shows why it should not have been made.

### What is left

The next question is the switch's own configuration, and this host cannot read
it off the wire. What the wire does say is already exhausted: the switch is LACP
active, it advertises all four ports as aggregatable, it answers on all four
links, and it runs on default partner information. Everything this end can vary
has been varied — one machine per link, four ports offered, the uplink tag, the
destination override, per-port source addresses — and none of it changed
`DEFAULTED`.

### The BMC procedure, corrected

Two things written down after earlier boots were wrong, and cost about an hour
here:

* **`rdmount` mappings are not session-scoped.** After the previous boot this was
  reported as *"media unmapped (session-scoped, ended)"*. It was not: killing the
  SSH session left `bhaskix-memmac.iso` mapped with `Mounted: true`, and it was
  still there an hour later.
* **Redfish virtual media works.** The Lenovo `RemoteMap` service — POST to
  `MountImages`, then `LenovoRemoteMapService.Mount`, and `UMount` to clear —
  mounts, unmounts and reports state correctly, and needs no shell session at
  all. It had been recorded as returning HTTP 500.

That matters because the XCC allows **two** concurrent command-shell sessions and
no more (`CommandShell.MaxConcurrentSessions`), so a procedure that spends one on
the media leaves exactly one for the console. Both were stuck held after the
previous boot and did not free in fifty minutes of quiet; the project lead
approved a `Manager.Reset`, which cleared them in about 210 seconds and also
cleared the stale mapping. Mounting over Redfish spends none, so a boot now needs
one session rather than two.


### The six frames were never lost — 2026-09-10

**The two numbers are not read at the same time, and the later one is bigger for
that reason alone.**

`report_net_domain` prints the `net x722` lines, including the VSI and MAC
multicast counts. `bin/ipd`'s LACPDU count is printed by
`report_net_after_exchange`, and between the two the kernel waits:

| wait | for | up to |
|---|---|---|
| `for _ in 0..50 { wait_millis(100) }` | DHCP | 5 s |
| `for _ in 0..80 { wait_millis(50) }` | the ring | 4 s |
| `LACP_PATIENCE_MS` | LACP to aggregate — and on this wire it never does | 90 s |

So `44 LACPDUs sent` is sampled up to **ninety-nine seconds** after `38 multicast
frames left the vsi`. Across that window the switch keeps sending LACPDUs, and
`bin/ipd` answers every one of them.

**That it answers every one is exact arithmetic, not an estimate.** `sent` minus
`heard` is `LACP_OPENINGS × machines` in every boot this project has recorded:

| boot | sent | heard | difference | machines |
|---|---|---|---|---|
| two ports | 23 | 7 | **16** | 2 |
| four ports | 44 | 12 | **32** | 4 |
| four ports | 47 | 15 | **32** | 4 |

Eight openings per machine, and one reply per frame heard. Every LACPDU
`bin/ipd` counts is either one of the thirty-two openings — all sent at
start-up — or a reply to a PDU that arrived, and the PDUs arrive across the whole
boot. Replies sent during the ninety-nine-second window are in `bin/ipd`'s count
and cannot be in a device counter that was printed before them. Six is exactly
the size that window would produce.

**So "why do six frames never reach the VSI" has a likely answer of "they do, and
they reached it after the counter was printed"** — and this is the project's own
recurring error in a new form. The three earlier ones were quantities nobody
measured, read as measurements of zero. This is two quantities measured at
different times, subtracted as though they were simultaneous.

**The instrument, so the next boot settles it rather than argues it.** The kernel
re-reads `bin/netd`'s two transmit words beside the LACPDU count they are being
compared with, and prints them there:

```
ipd lacp       44 LACPDU(s) sent, 12 slow-protocol frame(s) heard back
               and the device now counts 44 out of the vsi and 44 out of the mac
               -- every one of them reached the wire
```

An LACPDU is multicast and nothing else this bond sends is — announcements are
broadcast and DHCP is broadcast — so with both read together the arithmetic is
exact. Equal means every frame reached the wire and the gap was sampling; short
means the difference is real, measured at one instant, and worth hunting. The
line prints only where the driver set the *measured* bit, which needs an X722, so
no lane's output changes.

**Two things read while looking, which are real and are not this.** Neither
explains the gap, and both are worth writing down rather than rediscovering:

* `carry_x722` takes a frame out of `bin/ipd`'s ring and then, if `post_frame`
  returns `None`, drops it with nothing counting the drop. `post_frame` returns
  `None` only when no ring is attached or the ring is shorter than the
  descriptors a frame needs, so it should not fire — but *"should not fire"* and
  *"is known not to have fired"* are the distinction this document keeps being
  about.
* When `bin/ipd` names a member `bin/netd` does not hold, the frame leaves by the
  *active* member instead. For an ordinary frame that is right. For an LACPDU it
  is not: the PDU carries the port id of the link it speaks for, so sending it
  out of another link tells the switch something false. It cannot fire while all
  four members are held, which is every boot so far.

`take_from_ipd_into` is clean, and that was checked rather than assumed: every
early return happens before the ring's tail advances, so nothing is consumed and
dropped there.


### The device counters were never per-boot — 2026-09-10

The same-instant line was built to settle whether six frames were lost. It
settled something larger instead, and in the opposite direction to the section
above it.

**First it refuted the sampling explanation.** Read at one instant:

```
ipd lacp   43 LACPDU(s) sent, 11 slow-protocol frame(s) heard back
           and the device now counts 38 out of the vsi and 38 out of the mac
           -- fewer than were sent, read at the same instant
```

So the gap was not two clocks. Good — the instrument earned itself, and the
section above is wrong where it guessed.

**Then a second reading, with the split added, said there was no loss at all:**

```
ipd lacp   35 LACPDU(s) sent, 15 slow-protocol frame(s) heard back
           and the device now counts 38 out of the vsi and 38 out of the mac
           bin/netd posted 63 frame(s), 36 of them uplink-tagged, 0 refused
           -- every one bin/ipd sent reached a descriptor
```

`0 refused`, and 36 uplink-tagged posts against 35 LACPDUs — every frame
`bin/ipd` handed over reached a descriptor. Those two numbers are `bin/netd`'s
own, kept per boot, and they answer the original question: **nothing is lost
between `bin/ipd` and the ring.**

**And the two readings disagree, which is the finding.** 43 against 38 says loss;
35 against 38 says none. What is constant across them is the **38**.

> `GLV_MPTCL` and `GLPRT_MPTCL` are *"totals since power-on, not for this
> boot"* — the crate's own doc comment, at both readers — and nothing baselined
> them.

This machine is warm-restarted between boots far more often than it is
power-cycled, so a raw reading carries the previous boot's traffic into this
one's report. Three boots printed **38** while the traffic behind it went from 43
LACPDUs to 35. A number that does not move while the thing it counts does is not
measuring that thing.

So every subtraction in the two sections above was between a per-boot count and a
possibly-cross-boot total. The conclusion *"38 out of the VSI, 38 out of the MAC,
the wire is where they went"* is not withdrawn — the VSI and MAC agreeing with
each other is still meaningful, since both are totals over the same window — but
**any comparison of either against `bin/ipd`'s count was unsound**, in both
directions, and the "six lost frames" that started this was one of them.

**`since` existed for exactly this and had no caller.** `VsiTransmitted::since`
and `PortTransmitted::since` are written, documented and tested, and outside the
crate's own tests nothing called them. That is the **third** mechanism in this
driver to be written, documented and never called — after `TX_SWTCH_UPLINK`,
which cost three days, and the `GLPRT_*` constants, which cost this whole line of
questioning. The pattern is now the most reliable finding in this document: *a
mechanism nobody calls is not a mechanism*, and the way it presents is a report
that looks complete.

`bin/netd` takes a baseline before it sends anything and publishes differences
now, and the report says `since bring-up` where it used to imply this boot.

**Two limits of the instrument, stated so they are not rediscovered as bugs.**

* *"The same instant"* is same-**print**, not same-cycle: `bin/ipd`'s page is
  snapshotted just before `bin/netd`'s words are read, so the two can differ by a
  frame in flight. 36 posted against 35 sent is that, not an impossibility.
* The device's multicast count legitimately **exceeds** the LACPDU count, because
  IPv6 neighbour discovery is multicast too. `uplink_posted` is the like-for-like
  number, and it is why that counter is kept apart from `sent` — which in turn
  counts the bond's broadcast announcements and cannot be compared with either.

**And one earlier claim in this document is withdrawn.** It said `sent` minus
`heard` is `LACP_OPENINGS × machines` in every boot. It is not: this boot reads
35 − 15 = 20, because a reply consumes an opening pass, so replies arriving
during the opening burst reduce the openings actually sent. The rule is
`openings_used × machines + replies`, with `openings_used ≤ LACP_OPENINGS`. The
three boots that fitted the simpler rule were the ones whose partner answered
late.


### Where the frames stop, measured — 2026-09-10

With the counters baselined and the write-back question asked, the chain is
measured end to end at one instant:

```
ipd lacp   35 LACPDU(s) sent, 15 slow-protocol frame(s) heard back
           and the device now counts 14 out of the vsi and 14 out of the mac since bring-up
           bin/netd posted 63 frame(s), 36 of them uplink-tagged, 0 refused
                  -- the device took them and did not send them
           36 of those posts were never written back (32 of them uplink-tagged);
           transmit cursor 13 against the device's head 6
                  -- not fetched: the head is behind
```

| boundary | verdict |
|---|---|
| `bin/ipd` → ring → descriptor | **clean** — 36 posts for 35 sends, `0 refused` |
| descriptor → device | **stalled** — 32 of 36 uplink posts never consumed |
| VSI → MAC | **clean** — 14 and 14 |

**And it is not a uniform failure.** Split by kind: 32 of 36 uplink-tagged posts
were never written back (89%), against 4 of the other 27 (15%). `QTX_HEAD` is
*behind* the driver's cursor — 6 against 13, summed across four members — so the
device is not fetching those descriptors at all. It does not fetch and drop them;
it stops fetching.

That is the whole three-day shape of this RFC in one measurement: the LACPDUs are
exactly the frames carrying the uplink tag, and exactly the frames the switch
never receives.

### The context descriptor is correct — §38.31.2.2.1, read

The obvious suspect was the descriptor the tag rides in. It is **not** the
defect, and this was checked field by field rather than assumed. The driver
writes qword 0 = 0 and qword 1 = `0x0101`:

| field | bits | required | written |
|---|---|---|---|
| `DTYP` | 0:3 | `0x1`, *"stands for a LAN context descriptor"* | `0x1` |
| `SWTCH` | CMD 5:4 = qword 1 bits 9:8 | `01b`, *"uplink packet… bypassing hardware filters"* | `01b` |
| `TSO` | CMD 0 | clear | clear |
| `TLEN` | 47:30 | *"if the TSO flag is cleared, the TLEN should be set by software to zero"* | 0 |
| `MSS`/`TARGET_VSI` | 63:50 | *"if both the TSO flag is cleared and the SWTCH field is not equal to 11b then this field should be set to zero"* | 0 |
| tunnelling / `L2TAG2` | qword 0 | unused | 0 |

Every field is what the datasheet asks for. The suspect is cleared.

### What §38.31.2.2.1 pointed at instead, which is a hypothesis and not a finding

Two sentences elsewhere in the same chapter are worth more than the descriptor
check was.

**The first settles that the approach is right.** §38.28's *Control VSI*: *"Any
VSI can be used as a control VSI as long as the adequate packets are routed to
it. A control VSI should have the Allow Destination Override flag set to enable
it to bypass the switch when sending packets."* So there is no separate
make-this-a-control-VSI bit; the flag this driver already sets, and that the boot
reports as *taken*, is the mechanism. And *Transmitting Packets from a Control
VSI* describes this exact case: *"A control VSI might need to send directed
multicast packets… According to the regular forwarding rules of the switch, such
packets are forwarded back to the control port or dropped. To overcome this, the
control VSI should set the SWTCH field."*

**The second is the lead.** *"At initialization time, the control VSI of the MAC
is assigned to the EMP. If at a later stage, one of the PFs decides to take
ownership of this control port, it should assign one of its VSI as the control
port of the MAC. The EMP should be notified of the change using **Stop LLDP
Agent** command and should disconnect the EMP control port."*

On this machine the EMP — the manageability firmware the BMC drives — holds the
MAC's control port, and it is demonstrably active: the switch's LLDP arrives
here every thirty seconds or so, and `bin/ipd` refuses those frames by
EtherType `0x88cc` on every boot. So this driver is asking to bypass the switch
from a VSI that has the Allow Destination Override flag but is **not** the
control port of the MAC, while another owner holds it.

That is consistent with everything measured — uplink-tagged descriptors accepted
and not consumed, ordinary ones fine — and it is **a reading of the
specification, not a measurement.** It is written here as the next thing to test,
with two cautions that belong with it:

* `Stop LLDP Agent` changes what the *management firmware* does, not just what
  this driver does, and this is a live cluster node whose BMC has reasons to run
  an LLDP agent. Whether the change survives a power cycle is not established.
  It is not a command to send casually, and not one to send without the machine's
  owner deciding.
* The alternative reading is simpler and cheaper to test: the ring is eight
  descriptors deep, an uplink frame takes two, so four fit — and this driver
  posts the next frame anyway when a write-back does not arrive, overwriting a
  descriptor the device has not fetched and a packet buffer every frame of that
  member shares. That would turn one stall into a run of them, which is the shape
  of 32 out of 36.

Neither is established. What is established is the boundary: **the frames reach
a descriptor and the device does not fetch it.**


### The fetch granularity, and a regression of my own — 2026-09-10

38.30.2.1, on descriptor fetch policy:

> *"During normal operating mode, the PXE_MODE flag must be cleared by
> software… **When the PXE_MODE flag is cleared, software should bump the tail at
> the entire 8 × descriptors granularity.** In this mode, hardware fetches
> descriptors in the entire cache lines (4 × 32 byte descriptors or 8 × 16 byte
> descriptors)."*

`bin/netd` clears PXE mode at bring-up, and these are 16-byte descriptors, so the
device fetches **eight at a time**. The transmit ring held exactly eight — one
cache line — and an uplink frame takes two descriptors, so its frames could never
fill a line without wrapping onto themselves. **The receive ring already honoured
the rule**: `bin/netd`'s own constant reads *"a whole multiple of 32 outside PXE
mode"*. It was learned once, written down on one side of the driver, and never
applied to the other.

**Then I made it worse, and the machine said so.** The first attempt changed two
things at once: the ring from 8 descriptors to 32, *and* padding every line out
with NOP descriptors so the tail always landed on a boundary. On the SR550:

| | before | after |
|---|---|---|
| multicast out of the VSI | 14 | **0** |
| posts never written back | 36 of 63 | **70 of 71** |
| uplink posts never written back | 32 of 36 | **44 of 44** |
| device head vs cursor | 6 vs 13 | **0** vs 88 |

The transmit head did not move at all. That is worse than the partial fetching it
replaced, and — because two things changed together — **it names neither of them
as the cause**. Either would do it: a queue length the device will not run, or a
line ending in six trailing context descriptors that the device reads as a
command whose data descriptor never arrives.

Reverted, and the depth re-landed alone. The padding stays out until the depth by
itself has been measured. That is the whole correction: changing one thing at a
time is not a style preference on a machine that costs a reboot to ask.

**And nothing gated the shipped depth.** Both existing ring tests attach their
own local depth — 8 and 4 — so `TRANSMIT_DESCRIPTORS` could have been any value
at all and every test would still have passed. It was 8 for months on that basis.
Compile-time assertions beside the constant now hold it to 38.31.3.4.2's own
rule — *"at smaller queue size than 32 descriptors the QLEN must be a whole
number of 8 descriptors. At a larger size than 32 descriptors, QLEN must be a
whole number of 32"* — plus the fetch line and the 2048-byte page it shares with
the packet buffer. A build is the right place for it, as it is for the register
tables: these are constants, so a *test* asserting them is a test that cannot
fail at run time, and clippy says so. Watched red at a depth of 12, where the
crate no longer compiles: *"QLEN must be a whole number of 8 descriptors below
32, and of 32 above it"*.

**What this predicts, so the next boot can falsify it.** A deeper ring does not
make the tail land on a line boundary; it makes four lines available instead of
one, so a frame is less likely to be overwritten before the device gets to it.
If the head starts moving and the multicast count climbs, the depth was the
constraint. If it reads as it did before — head short of the cursor, most posts
unwritten-back — then the granularity is the constraint after all and the padding
is the thing to get right, one change at a time.


### Where the padding goes decides whether the queue runs at all — 2026-09-10

The depth landed alone and helped. The padding was then tried alone, twice, and
the two placements are opposite results on the same depth and the same command
line:

| | no padding | NOPs **behind** the frame | NOPs **in front** |
|---|---|---|---|
| `QTX_HEAD` vs cursor | 10 vs 59 — behind | **0 vs 88 — dead** | **31 vs 24 — caught up** |
| plain frames unwritten | 0 of 27 | 26 of 27 | 0 of 27 |
| uplink frames unwritten | 24 of 32 | 44 of 44 | 27 of 36 |
| multicast out of the VSI | 18 | **0** | 19 |

**A NOP is a context descriptor, and a context descriptor is also how a command
begins.** Six of them at the end of a fetched line read as a command whose data
descriptor has not arrived, and the device waits — which is a head pinned at
zero and nothing transmitted at all. In front of the frame they sit between the
previous command's `EOP` and this one, the line ends on a data descriptor, and
**the device consumes everything the driver posts.** 38.31.2.1.2's *"permitted
only between commands"* is satisfied either way on a plain reading; only the
machine distinguishes them.

So the ring side is now correct, and it was a real defect: the receive ring
honoured the fetch granularity and the transmit ring never did. Plain frames went
from 85% completed to **27 of 27**.

**And the frames still do not go out.** 18 → 19 multicast is not a result. What
changed is *where* they stop, and the report's own verdict flipped from *"not
fetched: the head is behind"* to *"fetched and dropped: the head caught up and
the write-backs did not"* — which is the discrimination that line exists for.

**The device now fetches uplink-tagged descriptors and discards them without a
write-back, while plain frames are perfect.** That is as specific as this side
can get, and it is no longer a statement about the ring. It points at the
control-VSI reading recorded earlier: the EMP holds the MAC's control port, this
driver's VSI carries the Allow Destination Override flag but is not that control
port, and §38.28 says a PF taking ownership *"should notify the EMP using Stop
LLDP Agent"*. Sending that command changes the management firmware's behaviour on
a live cluster node, so it is the machine owner's decision and not a thing to try
casually.

### A build defect that invalidated a boot, and three others like it

The first attempt at the padding alone measured *nothing at all* — every figure
byte-identical to the boot before it, including a transmit cursor of 59, which
cannot be a sum of four multiples of eight. The image did not contain the change:
`bin/netd` in it was built forty-five minutes before the edit.

Its make rule named its own sources and two crates:

```make
$(USER_NETD): $(NETD_DIR)/src/main.rs $(NETD_DIR)/link.ld $(NETD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard device/src/*.rs)
```

`bin/netd` links `bhaskix-i40e`, and `i40e/src` is not there — so a change
confined to that crate never rebuilt it. **A survey of every user-binary rule
found four that could ship a stale binary**: `netd` missing `i40e`, `blkd`
missing `device`, `linuxd` missing `elf`, `rand` and `sock`, and `shell` missing
`pkg`. All four are fixed, and the fix was proven rather than assumed — `touch
i40e/src/lib.rs` now rebuilds `netd`, where before it did not.

The earlier boots are unaffected, and that was checked rather than hoped: each of
them also changed `user/netd/src/main.rs`, so the rule fired for a reason that
had nothing to do with the crate the change was in.

**A second boot was wasted for a reason of my own.** The previous serial session
was still attached, so the next `console 1` was refused with `clish launch
SerRedir exist` and the machine booted blind. The BMC allows one console session:
closing it belongs to finishing a boot, not to tidying up afterwards.


### `Stop LLDP Agent` succeeds, and always has — 2026-09-10

The control-VSI reading was the last hypothesis standing. It is dead, and the
way it died is the pattern this document keeps recording.

```
net x722   stop lldp agent: firmware took it -- the control port of the mac,
           which 38.28 says a driver taking it must ask for
net x722   22 multicast frame(s) left the vsi by its own count since bring-up
ipd lacp   45 LACPDU(s) sent, 13 slow-protocol frame(s) heard back
           bin/netd posted 75 frame(s), 48 of them uplink-tagged, 0 refused
           36 of those posts were never written back (36 of them uplink-tagged)
```

**Firmware hands over the control port when asked.** So the EMP holding it is not
why uplink-tagged frames die. The switch is unchanged — `0x45`, `DEFAULTED`,
partner key 0, port 0.

**And the command was never missing.** `OPCODE_STOP_LLDP_AGENT`, `LLDP_SHUTDOWN`
and `Device::stop_lldp_agent` were already in `bhaskix-i40e`, with the stop /
shutdown distinction already reasoned out in a doc comment — *"Stop is the
reversible half"* — and `bin/netd` already called it, on every boot since it was
written:

```rust
let _ = device.stop_lldp_agent(admin, false, SPINS);
```

The answer went on the floor. So whether this driver held the control port was
unknown for the whole of this investigation, while the section above named it as
the leading explanation.

That is the **fourth** mechanism in this driver to be written, documented and
never checked, after `TX_SWTCH_UPLINK`, the `GLPRT_*` constants and
`VsiTransmitted::since`. It differs from the other three in kind, and the
difference is worth keeping: this one *was* called. Only its result was
discarded. A mechanism nobody calls and a mechanism whose answer nobody reads
are the same blindness one layer apart, and the second is harder to see, because
every grep finds a caller.

### A CPU uncorrectable error on the SR550, 2026-09-10

**The machine logged a critical processor fault during this boot, and it is
recorded here because it happened, not because it is understood.**

```
2026-09-10T14:29:52.810Z  Critical  An Uncorrectable Error has occurred on CPUs.
2026-09-10T14:30:23.404Z  Critical  An uncorrectable error has been detected on processor 1.
```

The `ForceRestart` that began this boot went out at **14:28:51Z**, so the first
entry is **sixty-one seconds** later. On this machine POST takes four to five
minutes — measured across today's boots, where the first Bhaskix console line
never appears sooner — so the fault was logged while firmware was still running,
before this image loaded.

**That is evidence and not exoneration.** This node was force-restarted many
times over one day to answer the questions above, and a driver that programs a
NIC's DMA is not a thing to declare innocent from a timestamp. What can be said
precisely:

* Redfish reports the system `Health: Critical`, `HealthRollup: Critical`,
  `State: Enabled`; `ProcessorSummary` health `Critical`; processor 1 health
  `Critical`; memory `OK`, 192 GiB.
* The boot completed and printed its whole report afterwards, so the machine
  went on running.
* The two entries are the only ones in the BMC's active log. The standard log's
  most recent entries are from 2026-07-21 and are unrelated drive faults that
  recovered.

**The log has been left intact and the machine has been left alone.** Clearing a
hardware fault record destroys the evidence for whoever looks next, and this is
somebody's cluster node rather than a test rig. No further boots were made after
the fault was found.

**What this costs the work.** Every measurement in this document that came from
this machine was taken before that entry, on a machine reporting healthy — but
the last boot's numbers were taken from a machine that had just logged an
uncorrectable processor error, and they should be read with that beside them.
The `Stop LLDP Agent` result above is a firmware answer to an admin command,
which is about as robust a reading as this report contains; it is not withdrawn,
and it is not independent of a machine in this state either.


### The last unverified link in the uplink path — 2026-09-10

The question left standing is narrow: the device fetches an uplink-tagged
descriptor, transmits some of them, and mostly does not write one back, while
plain frames are 27 of 27. The only difference between the two is the context
descriptor carrying `SWTCH = 01b`.

**Four things were ruled out from the datasheet rather than by reasoning.**

* The **context descriptor is correct** — `DTYP` `0x1`, `SWTCH` `01b` at qword 1
  bits 9:8, `TSO` clear, `TLEN` and `MSS` zero, checked field by field against
  §38.31.2.2.1.
* The **VSI buffer offsets are correct**. Table 38-216 puts *"allow destination
  override"* at byte **6.0** and *"switching section is valid"* at Valid Sections
  bit **0**, which is what the driver writes.
* The **read-modify-write reads what it writes**. Table 38-224: the Get VSI
  Parameters response buffer is *"same parameters as listed in Table 38-216"*.
  This was checked because a mismatched layout would have explained everything at
  a stroke — firmware accepting a command that wrote a switch id where a flag
  belonged.
* The **line structure is not it**. With the padding in front, a plain frame and
  an uplink frame have the same shape: NOPs, then the command, data descriptor
  last, one `RS` per line. Plain frames complete every time.

**What is left is the fifth instance of one pattern.**
`allow_destination_override` does the read-modify-write and reports whether
`Update VSI` was **accepted**. It never reads the bit back. Without that bit a
switch control tag is *"not permitted"* — and an accepted command whose bit did
not stick reads exactly like a working one, which is how this path has been
reported healthy while every frame carrying the tag died.

That is the same shape as `TX_SWTCH_UPLINK` with no caller, the `GLPRT_*`
constants with no reader, `VsiTransmitted::since` with no baseline, and
`stop_lldp_agent`'s discarded result. Five times, in one driver, over one line of
questioning. The lesson has stopped being *"a mechanism nobody calls is not a
mechanism"* and become the more uncomfortable general form: **anything this
driver has not read back, it does not know.**

So the section is read back and published as read — the flag, and with it the
switch id and both loopback bits, because setting the flag rewrites the whole
switching section and a mistake there would show as one of those moving when
nothing asked it to. The decode is held to Table 38-216's own byte and bit
numbering by a host test, watched red by reading byte 6.**1** — the *security*
section's VLAN anti-spoof — as the override.

**This is an instrument and not an answer.** It will print either

```
the vsi's switching section reads back: destination override set, switch id N, loopback a/b
```

or `CLEAR -- the command was taken and the bit is not there`, and only the
machine can say which. The SR550 is reporting a critical processor fault and has
been left alone, so this is what to run first on a healthy one.


### The verdict line was doing arithmetic that wraps — 2026-09-10

**A correction to two earlier readings in this document, and to a conclusion
drawn from them.**

The report compared *"transmit cursor N against the device's head M"* by summing
both across four members. Four cursors wrapping independently at 32 make that
comparison flip on arithmetic alone, and it did:

| boot | printed | the packing |
|---|---|---|
| leading NOPs | *"head 31 against cursor 24 — caught up"* | padding in front |
| read-back | *"head 15 against cursor 88 — behind"* | padding in front |

Same code, same packing, opposite verdicts. **The first was read as evidence that
the leading-NOP padding had fixed the fetch.** It was evidence of a wrap.

`Device::transmit_outstanding` counts around the ring instead —
`(tail - head)` modulo the depth, per member, then summed, which is a *count* and
so means something added up. Its host test builds exactly the trap: the cursor
wrapped to zero with the head mid-ring, so the head reads *higher* than the tail.
Against the old subtraction it reports **0** outstanding where **24** descriptors
are pending.

**What the corrected instrument says**, on the boot after:

```
30 of those posts were never written back (30 of them uplink-tagged);
49 descriptor(s) still unconsumed, worst ring 16
       -- not fetched: descriptors are sitting in the ring
```

Forty-nine descriptors unconsumed across four rings, the worst holding sixteen of
its thirty-two. **The device is not fetching them.** So the padding never fixed
the fetch, and the section above that credits it with doing so is wrong on that
point — what it fixed was the queue *stopping altogether*, which trailing NOPs
caused and leading NOPs do not.

**The signature, on numbers that can now be trusted:**

| | posted | never written back |
|---|---|---|
| plain frames | 27 | **0** |
| uplink-tagged | 40 | **30** |

Plain frames are consumed promptly and complete every time; lines carrying an
uplink-tagged frame accumulate. That rules out the device merely being slow,
which would hit both alike.

And every precondition remains verified present in the same boot: `destination
override set, switch id 2` read back off the device, and `stop lldp agent:
firmware took it`.

**The lesson, which is the same one again in a new place.** Four times this work
found a mechanism whose result nobody read. This is the fifth kind: a number that
*was* read, printed, and reasoned from — and was arithmetic rather than
measurement. The write-back counts were beside it the whole time, unchanged
across every one of those boots, and they were the ones telling the truth. **A
derived verdict is not evidence; the count it was derived from is.**


### The switch's own account of itself — 2026-09-10

RFC 0076 spent a week asking what the switch thinks of a port-channel this host
has no login to. The switch has been answering every thirty seconds and
`bin/ipd` refused the frames: `last refusal reason 2, on a frame of 171 bytes
with ethertype 0x88cc`. Sixth instance of the pattern, and the one where the
answer was arriving unasked.

```
lldp neighbour 9 tlv(s), 0 organizationally specific; chassis/port/ttl 1/1/1
lldp neighbour its port id, subtype 7: 0x786731320000
```

`0x786731320000` is ASCII **`xg12`** — port id subtype 7, *locally assigned*, so
the switch's own name for the port this link lands on.

**And zero organizationally specific TLVs.** That is the load-bearing part: a
link-aggregation TLV lives inside a type-127 organizationally specific TLV, and
so does DCBx. Nine TLVs, a walk reaching a clean end, and not one of type 127.

**What that does and does not establish.** It does not say the port-channel is
absent — plenty of switches never emit that TLV with a channel-group configured,
so what is ruled out is learning the answer *this way*. What it establishes is
that the switch is reachable, talkative, and names its port, so `xg12` is the
interface to look at if its configuration can be read directly.

**A limit of the instrument as built**, stated rather than discovered later: the
port id is a single global, while LLDP arrives on all four members. `xg12` is
whichever link's frame landed last.

> **Fixed the same day, and it was worth fixing.** Recorded per member, the four
> links report `xg12`, `xg11`, `xg10` and `xg9` — see below.

**Grounded rather than recalled.** Table 38-171 gives the TLV header as seven
bits of type and nine of length; 38-172 gives an organizationally specific TLV
as that header plus a three-octet OUI and a one-octet subtype; §38.29.4.2 names
types 0, 1, 2 and 3 and their subtypes. Everything else is left as an inventory
on purpose — Table 38-173 lists only DCBx for that OUI, so the aggregation TLV's
number is **not** grounded by anything in this project and the parser does not
pretend to know it. What the switch actually sends decides what is worth
decoding next.

Two host tests, watched red against the obvious misreading of the header as a
byte of type and a byte of length — which halves every type and shifts every
length, after which the walk wanders through the frame finding plausible
rubbish — and a truncated-frame test, since a neighbour's frame is hostile
input and reading past its end is the real danger.


### Four links, four switch ports — 2026-09-10

The port id is recorded against the link it arrived on now, and the answer is
not the one a single global could have given:

```
lldp neighbour the port it reaches, per link:
  link 0 subtype 7 "xg12", link 1 subtype 7 "xg11",
  link 2 subtype 7 "xg10", link 3 subtype 7 "xg9"
```

**Four distinct switch ports, consecutive, in reverse order of this bond's
members** — member 0 reaches the switch's `xg12`. So the physical topology is
confirmed from the wire rather than from description: four cables into four
adjacent ports of one switch, which is the shape a four-port channel-group
should have. And the switch's own names for them are now known, which is what a
question about its configuration needs: **`xg9` through `xg12`**.

Rendered as text because subtype 7 is *locally assigned* — a switch names its
ports the way a human would, so `"xg12"` is worth more than `0x786731320000`; a
non-printable id still falls back to hex.

Still **zero organizationally specific TLVs on all four links**, so no
aggregation TLV from any of them. That remains *cannot be learned this way*
rather than *there is no channel-group*.

**Why one word was the wrong shape**, since it is the general lesson: four links
reaching one port and four links reaching four are the two answers a
port-channel question turns on, and a single value cannot distinguish them. The
first version kept whichever frame landed last and would have reported `xg12`
either way. A per-thing question needs a per-thing instrument — the same
correction this document already made for the LACP machines, the link states,
the member addresses and the partner flags.


### The switch forwards nothing but link control — 2026-09-10

LLDP cannot answer what VLANs the switch tags, because a Port VLAN ID TLV is an
organizationally specific TLV and this switch sends none. But the tags are on
the frames themselves, and `bin/ipd` was discarding them: `EthFrame::parse_on`
refuses a foreign tag with `Unsupported { field: "802.1Q tag for another VLAN",
value: id }` — the id is *in the refusal* — and `refuse` recorded only the
reason. Seventh instance of this work's pattern, and the seventh where the answer
was already inside a value being thrown away.

Recorded per link, four VLANs deep, the machine answers:

**Nothing.** The `switch vlans` line does not print, and it is a real zero rather
than a suppressed print — the LLDP block immediately above it prints under the
same `complete` guard and does appear, so all four words are zero on all four
links. Corroborated by `ipd after`: **31 frames taken, 0 refused**. Every frame
that arrived was accepted, which on a VLAN-17-bound interface means every one was
untagged link control — LACP and LLDP. Not one 802.1Q tag crossed.

**What that is and is not evidence of.** It is consistent with what this document
already records as the reason DHCP goes unanswered: a switch does not forward
VLAN data to a channel-group member it has not bundled. The ports carry
link-level protocol only, which is exactly what an unbundled aggregation looks
like from this end — so it is *another consequence of the same unformed bundle*,
not independent evidence about the VLAN configuration.

What it does rule out is any theory in which the switch is forwarding VLAN 17 and
this stack mishandles the tag. Nothing tagged is arriving to mishandle.

The instrument is worth keeping regardless: the moment the channel-group bundles,
the report will say which VLANs arrive on which ports without another change.

### Where the question stands

Confirmed from the wire, none of it from description:

* Four cables into four adjacent ports of one switch — `xg9`, `xg10`, `xg11`,
  `xg12`, named by the switch itself.
* The switch is **LACP active**, answers on all four links, and records its
  partner as key 0 / port 0 — administrative defaults, so it has never accepted
  anything this host sent.
* It forwards **no data at all**, only LACP and LLDP.
* On this side: every precondition for an uplink-tagged transmit is verified
  present, and 25% of uplink-tagged descriptors complete while plain frames are
  100%.

The two ends of that are a host whose frames mostly do not leave the descriptor
ring, and a switch that has never heard a usable LACPDU. Whether those are one
fault or two is the open question, and this side has run out of things it can
vary.


### The driver was overwriting what the device still owned — 2026-09-11

The boot report has printed this for days and nothing acted on it:

> *not fetched: descriptors are sitting in the ring, and **this driver overwrites
> what it does not wait for***

`post_frame` posted regardless of what the device had consumed. With one frame
per cache line and four lines in the ring, a boot posting sixty-seven frames
rewrites the ring many times over — and a descriptor rewritten while the device
still owns it is a frame silently lost, plus a packet buffer changed under a
transmit in flight. Both of those are on this side, and neither needed the
switch to diagnose.

It refuses now, leaving one line free: `outstanding` is `(tail - head)` around
the ring, so a completely full ring is indistinguishable from an empty one and
the last line is never taken. The refusal lands in `post_refused`, which the
report already carries — so what was a silent overwrite is a counted fact.

**That matters for the measurement as much as for the correctness.** The SR550
has been reporting *30 of 40 posts never written back* with nothing able to say
whether those frames were lost or merely late.

`a_full_transmit_ring_refuses_rather_than_overwriting` fills the ring with a
device that consumes nothing, asserts the next post is refused **and that the
cursor did not move**, then consumes one line and checks exactly one more frame
fits. Watched red by deleting the guard: *"the ring is full and the next frame
must be refused, not written over one the device still owns"*.

**Three existing tests failed on the change**, because they encoded *post
regardless* — the fourth time in this work that tests have pinned behaviour that
turned out to be wrong, after the one-descriptor-per-frame packing, the tail
after an uplink pair, and the ungated ring depth. They advance `QTX_HEAD` after
each post now, modelling a device that keeps up, so they stay tests about
*packing* and the new rule gets a test of its own rather than being smeared
across four.

**What the next boot decides, stated before it happens.** If overwriting was the
cause, `post_refused` becomes non-zero and the write-back count climbs. If
`post_refused` stays zero while 30 of 40 still go unwritten, the driver was never
overwriting anything and the loss is elsewhere. Either way the result is clean,
which is more than the last several attempts could say in advance.


### The queue index, and why three ports in four never fetched — 2026-09-11

The device was not stopping the queues. `PF_MDET_TX` and `GL_MDET_TX` both read
clear and all four transmit queues read enabled, which kills the one explanation
the datasheet documents for a queue that stops:

```
malicious-driver record: none -- the device did not stop a queue on purpose;
transmit queues enabled 0b1111
```

That negative is what sent the question back to the index, and the index is where
it was.

**Two kinds of register, and they were treated as one.**

* `QTX_TAIL[Q]`, `QTX_ENA[Q]`, `QTX_HEAD[Q]`, `QTX_CTL[Q]` are *per-queue*
  registers reached through a function's own BAR, so the index is **PF-relative**
  — which this project established in step 1 with a page fault as the evidence.
* **`GLLAN_TXPRE_QDIS` is a `GL_` register**: one global array covering all 1536
  queues, in which `QINDX` is a *field* naming the queue. A BAR cannot
  disambiguate a field. The crate said so at `clear_transmit_queue_disable` —
  *"`queue` is the **absolute** index, which is what `QINDX` takes"* — and
  `bin/netd` handed it the PF-relative one, reading `FIRSTQ` only to discard it
  under a comment asserting it *"must not be added"*.

On PF0 `FIRSTQ` is zero, so the two coincide and it works. On PF1, PF2 and PF3 it
cleared some other queue's pre-queue-disable flag and left this one's set — and
38.31.3.1.1 requires that flag cleared **before the queue is enabled**. A queue
with it still set reads as enabled, records no error, and does not fetch
descriptors.

**The ratio is the tell, and it is exact:**

| | leaves by | completion |
|---|---|---|
| plain frames | the active member only — member 0 = **PF0** | **100%** |
| uplink LACPDUs | all four links, one per member | **~25%** |

Three of four failing is three of four functions with the wrong flag cleared.

**And it accounts for every negative result before it.** Queues enabled, no
malicious-driver event, destination override read back set, control port taken
from the EMP, context descriptor correct field by field — not one of those would
notice a pre-queue-disable flag left set on somebody else's queue.

`the_pre_queue_disable_register_names_its_queue_absolutely` pins both halves
using PF1's real base of 384: the register chosen is `absolute / 128`, and the
value carries the absolute queue in `QINDX`. The PF-relative index picks a
*different register* naming a *different queue* — wrong twice over, which is why
it could not half-work.

**Same class as the defect that cost step 1 several boots** — absolute against
PF-relative — and the same trap: invisible on the first function of a card. The
lesson this time is narrower and worth keeping: **a `GL_` register that names its
target in a field takes the absolute number; a per-queue register reached through
a function's window takes the relative one.** The prefix says which.

**The prediction, before the boot**: uplink completion goes from ~25% to near
100%, and the outstanding-descriptor count collapses.


### The padding was neither the cause nor a fix — 2026-09-11

The queue-index fix let PF1's queue fetch for the first time, and the device
immediately flagged what it found:

```
malicious-driver record: FLAGGED; transmit queues enabled 0b1111
queue 384, function 0, MAL_TYPE 21 -- the descriptor check this driver failed
```

Queue 384 is PF1's `FIRSTQ`, which is the queue the fix newly addresses. **The
prediction attached to that fix was wrong** — uplink completion did not go to
100%, it stayed at ~25% — but the change was not inert: it moved the blocker from
*the device is not looking* to *the device looks and refuses*.

**The table the C620 references but does not contain.** `GL_MDET_TX.MAL_TYPE`
points at a *"Malicious Driver - Tx descriptor checks table"* that is absent from
this datasheet. It is Table 7-138 of the X710/XXV710/XL710 datasheet, and event
**21 is four different checks**:

| Check | `GL_MDCK_TCMD` bit | Description |
|---|---|---|
| Tail update bigger than ring size | 7 `ENDLESS_TX` | Endless transmit ring |
| More than seven context descriptors | 12 `M_CONTEXTS` | 7 or more consecutive non-data descriptors fetched |
| Descriptor type | 14 `BAD_DESC_TYPE` | Illegal descriptor type used |
| No Packet | 15 `NO_PACKET` | Tail update not containing at least one full packet |

`M_CONTEXTS` matched the whole-line padding exactly: a NOP *is* a context
descriptor, and each padded line held seven consecutive non-data descriptors
before its data one — the threshold, to the descriptor.

**It was wrong.** With the padding removed entirely the flag is still there, same
queue, same code. So `M_CONTEXTS` is eliminated, and the padding is eliminated
with it: uplink completion returned to ~25% and `post_refused` to zero, which is
where it was before the padding existed.

> **Retracted and then restored, both on 2026-09-11.** The reasoning above
> requires that the flag read after the padding was removed be a *new* event,
> and for a few hours it could not be: `clear_malicious_transmit` wrote `0xFFFF`
> to an `RW1C` register whose `VALID` bit is 31, so the reading might have been
> latched from any earlier boot. With the clear fixed the record reads the same
> — `queue 384, function 0, MAL_TYPE 21`, with no padding in the ring — so the
> elimination stands on evidence that can now be trusted. See *A clear that did
> not clear* below, and the boot beneath it. **Across its whole life the padding
changed nothing in either direction**, and it cost several boots to establish
that. It came from reading the fetch-granularity rule as requiring aligned tails;
that reading is not supported by anything measured.

**Also eliminated: the queue index, in all three of its forms.** §38.26.3's
address formula settles it — `FPM_object_address = (GLHMC_{object}BASE * 512) +
(2^OBJSZ * element_index)` with `HMC_PM_index = PF index`, so the base is already
per-function and `element_index` is relative to it. The worked example says
*"512 LAN receive queues starting at index 0"*. `bin/netd` was right.

The crate's `ContextLocation` doc said the opposite, quoting step 5's *"HMC PM
LAN objects are indexed with the absolute queue number"* as though it were the
`element_index` rule when it is about **sizing the base and count registers**.
That comment is corrected in place, with the contrast spelled out: a `GL_`
register's field-named queue is absolute, a per-function object's element index
is not.

### What is left, and what it cost

`ENDLESS_TX`, `BAD_DESC_TYPE` and `NO_PACKET` remain, none with an obvious match
in what this driver posts. `GL_MDCK_TCMD` would say which checks are even
enabled, and **has no published MMIO address in either datasheet** — thirteen
mentions across the two, and the only addresses near them are the NVM words the
defaults load from.

**Today's net movement on the symptom is zero.** What was gained is elsewhere and
is real: the overwrite fix, the wrap-correct outstanding count, the
malicious-driver reader that surfaced event 21 at all, and this documentation
correction. Two confident hypotheses failed on hardware in one day, both of which
fitted the evidence before the boot. The next one should be cheaper to test than
a boot.


### A clear that did not clear — 2026-09-11

`ENDLESS_TX` and `NO_PACKET` were eliminated by reading the code rather than by
booting, which was the point: both arguments hold without hardware.

* **`ENDLESS_TX`** — *"tail update bigger than ring size"*. `QLEN` in the
  transmit context and the cursor's wrap in `post_frame` both come from the one
  constant `TRANSMIT_DESCRIPTORS`, so the tail cannot name a descriptor outside
  the ring the device was told about.
* **`NO_PACKET`** — *"tail update not containing at least one full packet"*.
  Both doorbell sites sit inside `if let Some(slot) = post_frame(…)`, so the
  tail is only ever rung after a data descriptor has been written.

Then the instrument that produced the evidence turned out to be broken.

```rust
const MDET_CLEAR: u32 = 0xffff;
```

`GL_MDET_TX` is `RW1C` with `VALID` at bit **31**, `MAL_TYPE` at 29:25 and
`PF_NUM` at 24:21. Writing `0xFFFF` clears `QNUM` and half of `VF_NUM` and
leaves the event itself standing — and a zero written to an `RW1C` bit is not a
clear, it is a no-op.

**Which half of the report this spoils, precisely.** `PF_MDET_TX.VALID` is bit
**0**, so `0xFFFF` did clear that one: `FLAGGED` has always meant *a malicious
event was raised against this function on this boot*, and that much stands.
`GL_MDET_TX` is the register that carries *what the event was* — the queue, the
function, the `MAL_TYPE` — and it was never cleared. It records the **first**
event since its last clear and holds it, so what has been read as "this boot's
details" is the first event this card ever raised under this driver, on any
boot.

That also answers a loose end this document has been carrying: `function 0` on
queue 384, which belongs to PF1. Not a puzzle about how the device numbers
functions — a record from a boot where the event really was PF0's, still
sitting there.

The C620 says *"once read, driver must write 0xFFFF to clear"* for all three MDET
registers. The X710 says the same rule generally and correctly: *"The registers
are cleared by writing ones to them."* The specific-looking number was believed
over the accurate sentence, and the register's own field table — printed two
lines above the constant, `VALID` at 31 — was not checked against it.

**What this puts in doubt.** The elimination of `M_CONTEXTS` rests on a
`MAL_TYPE` read back after a clear, and there was no clear, so it cannot be
relied on until a boot with a working one repeats it. (`BAD_DESC_TYPE` was never
eliminated — it has been on the "what is left" list throughout. An earlier
version of this section said the fix retracted that too, which was an
over-claim.) `ENDLESS_TX` and `NO_PACKET` are untouched, because neither
argument goes near this register.

What is *not* in doubt is that something is being flagged. `FLAGGED` came off
`PF_MDET_TX`, which was cleared properly. The device is refusing this driver's
descriptors; the next boot is the first that can say which check.

**The pattern, now counted.** Nine mechanisms in this driver were written,
documented, and then never called or never read back — `TX_SWTCH_UPLINK`, the
`GLPRT_*` constants, `VsiTransmitted::since`, `stop_lldp_agent`'s discarded
result, `allow_destination_override`'s unread bit, `transmit_queue_state`,
`Device::port_counters`, the VLAN tag `parse_on` discarded in its refusal, and
the LLDP frames refused on every boot. This is a tenth and a worse kind: a
mechanism that *was* called, on every boot, and did nothing. A clear that does
not clear reads exactly like a condition that persists.

And the test that covered it passed. It asserted that `MDET_CLEAR` was written
back to both registers — which any constant satisfies, including a wrong one.
The assertion now names the fields instead: a one must reach bit 31 and
`MAL_TYPE`, watched red against `0xFFFF`.

**Four tests were also lost.** The commit that dropped the padding removed
`outstanding_descriptors_are_counted_around_the_ring`,
`the_pre_queue_disable_register_names_its_queue_absolutely`,
`a_malicious_transmit_event_decodes_at_its_own_fields` and
`a_full_transmit_ring_refuses_rather_than_overwriting` along with the padding's
own test — five removed where one was meant. The mechanisms survived; only their
cover went, silently, because a suite that shrinks still passes. All four are
restored here, the two that describe `post_frame` rewritten for a ring with no
padding in it.


### The record, read once it could be trusted — 2026-09-11

With `MDET_CLEAR` writing every bit, the SR550 was booted again. The record is
unchanged:

```
malicious-driver record: FLAGGED; transmit queues enabled 0b1111
queue 384, function 0, MAL_TYPE 21
bin/netd posted 67 frame(s), 40 of them uplink-tagged, 0 refused
30 of those posts were never written back (30 of them uplink-tagged)
61 descriptor(s) still unconsumed, worst ring 20
```

**So the `M_CONTEXTS` elimination is restored**, and this time on a reading that
means what it says: event 21 is raised with no padding anywhere in the ring, so
it is not seven consecutive non-data descriptors. `no_run_of_seven_non_data_descriptors_is_ever_posted`
pins that in the crate.

**And event 21 now has one candidate left.** Of its four checks:

| Check | Status |
|---|---|
| `ENDLESS_TX` — tail update bigger than ring size | eliminated: `QLEN` and the cursor's wrap come from the one constant `TRANSMIT_DESCRIPTORS` |
| `M_CONTEXTS` — 7+ consecutive non-data descriptors | eliminated: no padding in the ring, and the flag is still raised |
| `NO_PACKET` — tail update without a full packet | eliminated: both doorbell sites are inside `if let Some(slot) = post_frame(…)`, and the data descriptor carries `EOP` and `RS` |
| **`BAD_DESC_TYPE` — illegal descriptor type used** | **the only one left** |

**A second, independent line points at the same place.** All 30 posts that were
never written back were uplink-tagged, and 30 of the 40 uplink-tagged posts
failed; the plain frames complete. The uplink path is the only one that writes a
**context descriptor**. A check named *illegal descriptor type* and a failure
confined to the frames carrying an extra descriptor type are the same finger
pointing.

That is not proof — `DTYP = 0x1` is what 38.31.2.2.1 calls a LAN context
descriptor, and `SWTCH` at qword-1 bits 9:8 is where `CMD[5:4]` puts it — so if
the encoding is wrong it is wrong in a field not yet compared against the table.
The next step is a field-by-field read of the context descriptor, which costs no
boot.

**Two corrections this boot forced, both of mine and both written hours before
it.** The retraction of `M_CONTEXTS` was correct to make and is now withdrawn by
measurement — that is the instrument working, not a mistake. The other two were
mistakes:

* The retraction claimed to withdraw an elimination of `BAD_DESC_TYPE`. There
  was none to withdraw; it has been on the *what is left* list since the table
  was found. Corrected above.
* It explained `function 0` on queue 384 as a stale record naming the function
  that raised it. **That explanation is dead** — the reading is this boot's. The
  real explanation is narrower and duller: `bin/netd` reads the record from
  **port 0's device only**, with the comment *"because the record is global"*.
  `GL_MDET_TX` is indeed global, but `PF_MDET_TX` is per-function, so `FLAGGED`
  is PF0's flag and no other member's is ever read. What `function 0` means
  cannot be settled without the per-member first-queue numbers, which the report
  does not print.

So the instrument is still not finished: it reads one of four functions, and it
reports a queue number with nothing to compare it to.


### The context descriptor, field by field — 2026-09-11

`BAD_DESC_TYPE` is *illegal descriptor type used*, and the context descriptor is
the only extra descriptor type this driver writes. So it was read against
38.31.2.2.1's table, every field including the ones required to be zero.

This driver emits `qword0 = 0x0`, `qword1 = 0x0000_0000_0000_0101`.

| Field | Bits | Written | Table |
|---|---|---|---|
| `DTYP` | qw1 3:0 | `0x1` | LAN context descriptor (Table 38-425; `0x0` data, `0x8` FD filter, else illegal) |
| `TSO` | qw1 4 | 0 | no segmentation |
| `TSYN` | qw1 5 | 0 | no 1588 timestamp |
| `IL2TAG2` | qw1 6 | 0 | no tag insert |
| `IL2TAG_IL2H` | qw1 7 | 0 | no inner VLAN |
| **`SWTCH`** | **qw1 9:8** | **`01b`** | uplink, bypassing hardware filters — `CMD[5:4]`, and `CMD` begins at qword-1 bit 4 |
| reserved | qw1 10, 29:11 | 0 | — |
| `TLEN` | qw1 47:30 | 0 | *"if the TSO flag is cleared, the TLEN should be set by software to zero"* |
| reserved | qw1 49:48 | 0 | — |
| `MSS`/`TARGET_VSI` | qw1 63:50 | 0 | *"if both the TSO flag is cleared and the SWTCH field is not equal to 11b then this field should be set to zero"* |
| tunnelling params | qw0 23:0 | 0 | `EIPT` 00b, `EIPLEN` 0, `L4TUNT` 00b, `L4TUNLEN` 0 |
| reserved | qw0 31:24 | 0 | — |
| `L2TAG2` | qw0 47:32 | 0 | nothing to insert; `IL2TAG2` is clear |
| reserved | qw0 63:48 | 0 | — |

**Every field is legal, including every field the table requires to be zero.**
The data descriptor beside it was checked the same way against 38.31.2.1.1 —
`DTYP` `0x0`, `EOP` at bit 4, `RS` at bit 5, `IL2TAG1`/`DUMMY`/`IIPT`/`L4T` all
clear, `OFFSET` zero (legal: `L4T` is `00b`, so `L4LEN` *must* be zero),
`BSIZE` at 47:34, `L2TAG1` zero as required when `IL2TAG1` is clear. And the
ordering rule holds: Table 38-425 lists context before data, which is the order
`post_frame` writes them.

Pinned by `a_context_descriptor_places_38_31_2_2_1s_fields`, watched red by
moving `SWTCH` to bit 4 — where it lands on `TSO` and the test names it.

**So the fields do not explain the event**, and the inference in the previous
commit is weaker than it was written.

**A correction to that commit.** It called the uplink-only signature *"a second,
independent line"* pointing at the context descriptor. It is not independent. A
malicious-driver event **stops the queue**, so every post after the stop fails
whatever it carries; the 27 plain frames are bring-up traffic and the 39 LACPDUs
run for ninety seconds, so "30 of 30 failures were uplink-tagged" is equally well
explained by *the queue stopped at a moment after which only LACPDUs were being
posted*. One correlation, confounded with time, described as two lines of
evidence. The discriminator is cheap and costs no reasoning: post a plain frame
*late*, after the failures begin, and see whether it completes.

**What the tables do rule out.** An over-fetch past the tail would read
descriptors this driver never wrote — but `shared::create` zeroes on allocation,
proven on this same boot by `memory hygiene a page written full of 0xa5 and
freed comes back zeroed to its next owner`. An all-zero descriptor is `DTYP`
`0x0`, a legal data descriptor with `BSIZE` 0, which trips `ZERO_BSIZE` (event
**23**) or `NO_PACKET`, not `BAD_DESC_TYPE`. So stale ring contents do not
explain event 21 by that route either.

**What is left is the record's own inconsistency**, and it is now the sharpest
thing on the table. `GL_MDET_TX` names queue **384** with `PF_NUM` **0**. Read as
an absolute queue, 384 is the second member's and belongs to PF1, not PF0. Read
as PF-relative, it is a queue on PF0 that this driver never posts to — it takes
one queue per port. Both readings are strange, and neither can be settled from
here, because the report prints no per-member queue numbers and reads
`PF_MDET_TX` — which is per-function — from port 0 alone.

Finish the instrument before trusting another reading off it: `PF_MDET_TX` per
member, and each member's absolute queue printed beside it.


### Finishing the instrument — 2026-09-11

Two gaps, both found by reading the code rather than by booting, and both of
the same kind: a reader that answers a narrower question than the one it is
asked.

**`PF_MDET_TX` is per port and was read from one.** `bin/netd` took the whole
malicious-driver record off member 0 with the comment *"port 0's, because the
record is global"*. `GL_MDET_TX` is indeed global — one register for the card,
holding the first event since it was cleared, whoever raised it. `PF_MDET_TX` is
**one register per function**. So `FLAGGED` has always meant *port 0 was
flagged*, and three members' flags have never been read on any boot this reader
has existed. `Device::malicious_flagged` reads that half alone, and the report
now carries one bit per member.

**The record names a queue and nothing was printed beside it.** `GL_MDET_TX.QNUM`
has read `384` for five boots, and whether that was a member's queue at all —
and whose — could not be said from the report, because the report contains no
member's queue number. It does now: each member's transmit queue in the device's
own numbering, thirteen bits each, at report word 39 with the flags, and the
kernel says outright whether the recorded queue is a member's and which.

The absolute number is `FIRSTQ + queue`, and `X722Queues::first` is kept for it.
Its neighbour's doc comment claimed `queue` was *"the absolute index of the
receive queue taken"*; it never was — it comes from `vsi_queue_base`, and
§38.30.3.4.2's *"'n' is the queue index within the PF space"* is the rule every
queue register but `GLLAN_TXPRE_QDIS` follows. Corrected in place.

**One thing noticed and deliberately left alone.** `clear_malicious_transmit` is
called once per member at bring-up, and each call clears the *global* register
as well as that function's. So the global record is baselined at the **last**
member's bring-up, not the first, and an event raised while members 0–2 were
coming up would be wiped by member 3's clear. It is harmless today because
nothing is posted to any transmit ring until every member is up — the rings are
attached at the end of bring-up and the first frame is sent later — so the last
clear still precedes all traffic. It is written down here because that is an
accident of ordering, not a property anything enforces.

This is the eleventh mechanism in this driver to be written, documented and then
asked a question it does not answer. The list is no longer interesting as a list;
what the entries have in common is that each one *looked* read.


### What the finished instrument said — 2026-09-11

```
malicious-driver record: FLAGGED; transmit queues enabled 0b1111
queue 384, function 0, MAL_TYPE 21
per member, its queue and its own flag: member 0 queue 0 FLAGGED; member 1 queue 384 clear;
                                        member 2 queue 768 clear; member 3 queue 1152 clear
the recorded queue 384 is member 1's
bin/netd posted 59 frame(s), 32 of them uplink-tagged, 0 refused
24 of those posts were never written back (24 of them uplink-tagged)
```

The register definitions leave no room to read these another way. 38.39.2.10.3:
`QNUM` is *"absolute queue ID on which the event was detected"*, `PF_NUM` is
*"PF/parent PF number on which the event was detected"*. 38.39.2.10.2:
`PF_MDET_TX.VALID` is *"a malicious event has been detected on **this
function**"*.

So the device is saying: **an event on absolute queue 384 — member 1's —
attributed to PF 0**, and the only function whose own flag is set is member 0.
The members sit at 0, 384, 768 and 1152, so `FIRSTQ` steps by 384 and each takes
queue 0 in its own PF space.

**The completion counts have been saying the same thing for boots.** The plain
frame site posts on `members[active]`, which is port 0; the uplink site posts on
all four. Across the two boots of 2026-09-11:

| | uplink posted | never written back | completed |
|---|---|---|---|
| first | 40 | 30 (75%) | 10 = 40/4 |
| second | 32 | 24 (75%) | 8 = 32/4 |

Exactly three quarters fail and exactly one member's worth completes, and the
member that completes is member 0. **So the failing set is not "uplink frames"
and not "late frames" — it is members 1, 2 and 3.** The correction written
earlier today said the uplink correlation was confounded with time; it was right
that the correlation was not independent evidence and wrong about the confound,
which is *which member*, not *when*.

**The hypothesis this boot was built to test next.** `QTX_CTL` is the only
statement of who owns a transmit queue — a receive queue's owner is implied by
the VSI that steers to it — and `own_transmit_queue` fills its `PF_INDX` from
`PF_FUNC_RID.FUNCTION_NUMBER`. If that window answers `0` on every member, then
`bin/netd` has told the device **PF0 owns all four transmit queues**. Queue 0 is
genuinely PF0's, so member 0 works; 384, 768 and 1152 are owned by a function
that is not the one posting to them, their descriptors are never fetched, and an
event on one of them is attributed to PF0 — whose flag is then the only one set.
Every line of the report above follows from that one reading.

It is a hypothesis. `own_transmit_queue` has written that register since the
transmit side existed and **nothing has ever read it back** — the twelfth
mechanism in this driver in that state. So the next boot reads it back, per
member, beside each member's `PF_FUNC_RID`, and the kernel says outright when a
queue's owner is not the function posting to it.

The datasheet's own wording is worth keeping in view either way: `PF_FUNC_RID`
gives *"the function number assigned to the function based on BIOS/OS
enumeration"*, in a register whose other fields are the PCI device and bus
numbers, while `QTX_CTL.PF_INDX` is *"index between 0 and 15"*. They coincide on
an ordinary card and are not defined to be the same thing.


### The owners were right, and that was the useful answer — 2026-09-12

```
per member, what it is and who owns its queue: member 0 is function 0, queue owned by PF 0;
  member 1 is function 1, queue owned by PF 1; member 2 is function 2, queue owned by PF 2;
  member 3 is function 3, queue owned by PF 3;
```

**The hypothesis is dead.** Every member reads its own `PF_FUNC_RID` and every
`QTX_CTL.PF_INDX` matches it. Nothing is mis-owned.

Two things came out of it anyway.

**The index convention is now confirmed rather than assumed.** Four distinct
values read back from four BARs at the same offset is proof that the per-queue
registers really are PF-relative through each function's own window. Until this
boot that had only ever been confirmed on member 0, where PF-relative and
absolute coincide — the exact blind spot that hid the `GLLAN_TXPRE_QDIS` bug for
days.

**And the malicious-driver line is retired.** Member 0 is the only function
flagged, and member 0 is the only member that *works*. Members 1, 2 and 3 carry
no malicious event at all; their descriptors are simply never fetched. So
`MAL_TYPE 21`, its four descriptor checks, and the context descriptor were never
the cause of this symptom — which is consistent with the field-by-field check
finding every field legal. The descriptors were always fine. Several days of
this document chase a register that was reporting something else.

### `RDYList` — 2026-09-12

Transmit context, Line 7, bits 84:93:

> `RDYList` — *"Transmit arbitration queue set. The RDYList index is **absolute**
> so it should be set to those RDYList allocated to the function."*

VSI parameters, Table 38-216, bytes 96-97:

> `QS_Handle 0` — *"The handle for queue set of TC0. **Bits [9:0] of this handle
> are used by software to program the RDYList field in the transmit queues
> context** for queues associated with TC0."*

`bin/netd` wrote `ready_list: 0`, hardcoded, for the life of the service. And
38.31.3.3 is what makes a wrong one silent:

> *"A queue context is fetched on demand (if not already in the cache) **when it
> is scheduled**. Then hardware fetches the transmit descriptors."*

Scheduling happens per arbitration queue set. A queue whose `RDYList` is not one
allocated to its function is never scheduled, so its context is never fetched,
so its descriptors are never fetched — and nothing errors, nothing is flagged,
and `QTX_ENA` still reads enabled. That is the symptom this document has
described from the start: *"descriptors are sitting in the ring, not fetched"*,
with `transmit queues enabled 0b1111`.

**Why member 0 worked.** PF0's handle is zero, so the hardcoded zero was
accidentally right for it. The third defect in this driver with that exact
shape, after `FIRSTQ` and `GLLAN_TXPRE_QDIS`: correct on function 0, wrong
everywhere else, and invisible until a second port was driven.

`VsiParameters::queue_set` has parsed those two bytes since the crate learned to
read VSI parameters, with a doc comment already saying *"its bits 9:0 are the
RDYList a transmit context needs"*, and `bring_up_x722` threw the whole reply
away but for `switching()`. The thirteenth mechanism in this driver written,
documented, and never read.

It is now read, written into the context, **and published per member at report
word 43** — because a value taken off the device and handed straight back is
exactly the kind nobody checks, and this document has a list of those.

**A note on the test, which was hollow first.** The assertion was written against
a `VsiParameters` built by hand in the test using the same expression the parser
uses, so corrupting the parser left it green: it compared a copy of the code with
itself. The parse is now `VsiParameters::from_context` and the test calls it —
watched red by moving the offset one byte, which the first version could not
have caught.


### The transmit path is fixed — 2026-09-12

```
per member, its transmit queue set (RDYList): member 0 0; member 1 1; member 2 2; member 3 3;
```

Exactly what the datasheet predicted: PF0's handle is zero, which is why the
hardcoded zero was invisible, and members 1-3 needed 1, 2 and 3.

| | before | after |
|---|---|---|
| uplink posts never written back | 30 of 40, 24 of 32 (75%) | **0 of 36** |
| descriptors unconsumed | 61, worst ring 20 | **4, worst ring 1** |
| malicious-driver record | FLAGGED, `MAL_TYPE 21` | **none** |
| out of the VSI / out of the MAC | 18 / 18, fewer than sent | **46 / 46** |

The report's own verdicts flipped with it: *"every one bin/ipd sent reached a
descriptor"*, *"the device finished with every one"*. The PF0 malicious event is
gone too, so even that was downstream of the same fault.

### Why the switch records key 0, port 0 — 2026-09-12

It is still `0x05` on all four links, and the switch still says:

```
the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
and records its partner as key 0, port 0 -- ours are key 1, port 1
```

`0x45` is `Activity | Aggregation | `**`Defaulted`**. Defaulted means the
switch's receive machine is running on administratively-configured partner
information — so `key 0, port 0` is **its own default**, not anything it read
from us. It has accepted no LACPDU from this host.

**Everything on our side checks out**, and all of it was verified rather than
assumed:

* The PDU matches 802.1AX byte for byte — subtype 1, version 1, actor TLV
  `0x01`/20 at offset 2, partner `0x02`/20 at 22, collector `0x03`/16 at 42,
  terminator at 58, 110 bytes.
* The actor identity is what aggregation requires: one system MAC for all four
  links, one key, distinct ports 1-4, priorities at the standard `0x8000`.
* The frame is untagged. `send_from` copies it verbatim, and the tagging path in
  `send` exempts link-control ethertypes anyway.
* Destination `01:80:C2:00:00:02`, EtherType `0x8809`, 124 bytes.
* They leave: 46 multicast out of the VSI, 46 out of the MAC, nothing unwritten.
* `allow_destination_override` is a read-modify-write that ORs in only the
  switching-section bit, so this driver does not disturb any other section.

That exhausts what software controls, which leaves the device altering the frame
on egress — and Table 38-216 has exactly one place where that happens silently:

| byte | field |
|---|---|
| 0-1 bit 2 | whether the VLAN handling section is valid at all |
| 8-9 | `PVID + Default UP` — *"VLAN ID to use in port-based VLAN insertion"* |
| 12 bit 2 | **`Insert PVID`** — *"port-based insertion of VLANs"* |
| 12 bits 0:1 | insertion mode — `10b` is *"admit .1Q tagged only"* |

`Insert PVID` puts an 802.1Q tag on every egress frame from the VSI. A switch
does not hand a tagged slow-protocol frame to its LACP machine, and **nothing
above the device could ever see it**: the bytes written are untagged, the MAC's
own counter still counts the frame out, and the partner just sits `Defaulted`.
An insertion mode of `10b` does the same damage from the other direction, by
refusing an untagged frame outright.

This card ran PXE before Bhaskix, so a firmware-left port VLAN is not a
hypothetical. And the section has been in the `Get VSI Parameters` buffer since
the first boot that ran the command, with only bytes 2-6 ever read out of it —
the fourteenth mechanism in this driver written, fetched, and never read. It is
decoded and published per member now, with the kernel naming either failure
outright.

The reading is still a hypothesis; what is established is that it is the only
remaining place the frame can be changed between this host and that switch.


### The VLAN section was not it either — 2026-09-12

```
per member, its vlan section: member 0 pvid 0, insert 0, admit 3, expose 3;
  member 1 pvid 0, insert 0, admit 3, expose 3; member 2 ... ; member 3 ...
```

Identical on all four and entirely permissive: no PVID insertion, insertion mode
`11b` *"allow all packets"*, expose mode `11b` *"do nothing"*. The VSI neither
tags a frame nor refuses one. Three hypotheses in a row now — `QTX_CTL`, the
descriptor checks, the VLAN section — each fitting the evidence beforehand and
each killed by a boot.

**What the same boot said that matters more:**

```
dhcp client    nobody answered -- FAILED
net reply      ipd built 11 frames, 0 arp mappings learned
tcpd           0 segments in, 7 out
```

**Nothing this host transmits has ever been answered by anything.** Everything
received is unsolicited — the switch's own LLDP and LACPDUs.

Half of that is circular and must be said so: a switch port in a channel-group
that has not bundled suspends data forwarding, so DHCP and ARP would fail anyway
while LACP is down. It is not independent evidence about the transmit path. What
it does establish is that there is **no independent probe of transmit from this
side**, which puts all the weight on a question the report has never been able
to answer.

### A sum is not a measurement — 2026-09-12

`bin/netd` reads both transmit counters **per member** — `vsi_transmitted(fact.vsi)`
and `port_transmitted(m.device.port_number())`, each against its own baseline —
and publishes only their sum. So

* four ports sending twelve frames each, and
* one port sending forty-six,

are the same line in every report this document has quoted. They are different
machines.

The second is what `SWTCH = 01b` would look like if *"transmitted to the network"*
resolves to the single switch element's uplink rather than to each VSI's own
port: every member's LACPDU leaves by one MAC, the total still reads 46, and
three of the four switch ports have heard nothing at all — `Defaulted` on three
links, for a reason nothing in the report could name. The card reports **1 switch
element**, which is what makes the reading possible rather than idle.

It does not explain link 0, and that is stated rather than smoothed over.

So the per-member counts are published at words 46 and 47, thirteen bits each,
with each member's MAC port number beside them — because *"which port did this
member read"* is the other half of believing the answer, and the three numbers
that agree on a single-port card (VSI, member index, MAC port) have already been
confused once in this driver.


### All four wires carry — 2026-09-12

```
per member, multicast out of the vsi / the mac: member 0 (mac port 0) 21/21;
  member 1 (mac port 1) 11/11; member 2 (mac port 2) 11/11; member 3 (mac port 3) 11/11;
```

Four **distinct** MAC ports, all four transmitting, and on every member the VSI
count equals the MAC count — nothing is lost between the VSI and the wire.
Member 0's 21 is its extra share: it also carries the bond's announcements.

So the single-uplink reading is dead, and with it the last structural
explanation on this side. **Four hypotheses killed in a row** — `QTX_CTL`, the
descriptor checks, the VLAN section, the single uplink — each fitting the
evidence before its boot.

### What was never done — 2026-09-12

Every fix in this work came from reading what the machine holds: `RDYList` out
of the VSI's own context, `GLLAN_TXPRE_QDIS`'s absolute index, the
malicious-driver clear that did not clear. The LACPDU has only ever been checked
by **reading the code that builds it** — `Pdu::write`, the TLV offsets, the
frame builder, the tagging exemption. That is the code checked against itself,
which is exactly the mistake the `QS_Handle` test made until its parse was
factored into `VsiParameters::from_context`.

The bytes that reach the device have never been printed, and neither have the
bytes of a switch LACPDU that arrives here and parses.

So both go on the report: thirty-two bytes of the last uplink-tagged frame,
taken out of the packet buffer the descriptor names, after the copy and before
the doorbell — and thirty-two bytes of the last slow-protocol frame the switch
sent, which is the one LACPDU on this wire known to be acceptable to something.
Thirty-two covers the Ethernet header, the subtype and version, and the whole
actor TLV: everything a switch reads before deciding an LACPDU is one.

**With both lengths, because a length is what code review cannot check.** An
LACPDU is 110 bytes behind a 14-byte header. A frame truncated anywhere between
`frame()`'s return and the descriptor's `BSIZE` reaches the switch short and is
discarded — and every counter in this report would still read exactly as it does
now: posted, completed, counted out of the VSI, counted out of the MAC. The
kernel says so outright when the sent frame is not 124 bytes.

If the two dumps differ in structure, that is the fault. If they do not, the
frame leaving this host is correct on the wire and what remains is the switch's
configuration — which is the one thing this machine cannot read.


### The frame is correct — 2026-09-12

```
lacpdu sent  124 bytes: 01 80 c2 00 00 02 08 94 ef 7a fc 90 88 09 01 01
                        01 14 80 00 08 94 ef 7a fc 8e 00 01 80 00 00 03
lacpdu heard 124 bytes: 01 80 c2 00 00 02 08 bd 43 76 47 e3 88 09 01 01
                        01 14 80 00 08 bd 43 76 47 e1 00 14 00 80 00 0a
```

| offset | ours | the switch's | |
|---|---|---|---|
| 0-5 | `01 80 c2 00 00 02` | `01 80 c2 00 00 02` | the Slow Protocols group address |
| 6-11 | `08 94 ef 7a fc 90` | `08 bd 43 76 47 e3` | the sending port's own MAC, both sides |
| 12-13 | `88 09` | `88 09` | Slow Protocols EtherType |
| 14-15 | `01 01` | `01 01` | subtype LACP, version 1 |
| 16-17 | `01 14` | `01 14` | actor TLV, length 20 |
| 18-19 | `80 00` | `80 00` | system priority |
| 20-25 | `08 94 ef 7a fc 8e` | `08 bd 43 76 47 e1` | system id, a card MAC on both sides |
| 26-27 | `00 01` | `00 14` | key: ours 1, theirs 20 |
| 28-29 | `80 00` | `00 80` | port priority |
| 30-31 | `00 03` | `00 0a` | port: ours 3, theirs 10 |

**Structurally identical**, same length, and the values that should differ differ
exactly as they should. The fifth hypothesis dies and the most useful one: the
frame itself is no longer under suspicion.

So the transmit path is proven end to end. A well-formed 124-byte LACPDU sits in
the buffer the descriptor names; it is posted, completed, counted out of the VSI
and out of the MAC, on four distinct ports. There is no unverified step left
between `bin/ipd` building an LACPDU and the wire.

**What those thirty-two bytes did not cover.** The partner TLV at frame offset
36, the collector at 56 and the terminator at 72 — and a receiver validates all
three before accepting an LACPDU. This driver's *parser* checks them on every
frame the switch sends, so the shapes are known-good; what has never been
confirmed is that its *writer* produces them. That is the same code-checked-
against-itself gap the first thirty-two bytes closed for the header.

Both dumps are the whole frame now, sixteen bytes a row with the offset in
front, so the two can be read against each other by eye and a field's position
counted rather than guessed.

If those three TLVs are right too then nothing this host emits is wrong, and the
remaining variable is the switch's configuration — which this machine cannot
read. That would be the point to say so plainly rather than keep going: the next
move needs switch access or a capture on the wire.


### The whole frame, and the end of what this side can answer — 2026-09-12

```
lacpdu sent    0: 01 80 c2 00 00 02 08 94 ef 7a fc 8e 88 09 01 01   (124 bytes)
lacpdu sent   16: 01 14 80 00 08 94 ef 7a fc 8e 00 01 80 00 00 01
lacpdu sent   32: 05 00 00 00 02 14 80 00 08 bd 43 76 47 e1 00 14
lacpdu sent   48: 00 80 00 0c 45 00 00 00 03 10 00 00 00 00 00 00

lacpdu heard   0: 01 80 c2 00 00 02 08 bd 43 76 47 e3 88 09 01 01   (124 bytes)
lacpdu heard  16: 01 14 80 00 08 bd 43 76 47 e1 00 14 00 80 00 0c
lacpdu heard  32: 45 00 00 00 02 14 00 00 00 00 00 00 00 00 00 00
lacpdu heard  48: 00 00 00 00 0d 00 00 00 03 10 00 03 00 00 00 00
```

| offset | field | ours | the switch's |
|---|---|---|---|
| 16-17 | actor TLV, length | `01 14` | `01 14` |
| 26-31 | key, port priority, port | `00 01`, `80 00`, `00 01` | `00 14`, `00 80`, `00 0c` |
| 32 | actor state | `05` | `45` |
| 36-37 | partner TLV, length | `02 14` | `02 14` |
| 38-51 | **partner identity** | `80 00`, `08 bd 43 76 47 e1`, `00 14`, `00 80`, `00 0c` | all zeroes |
| 52 | partner state | `45` | `0d` |
| 56-57 | collector TLV, length | `03 10` | `03 10` |
| 58-59 | collector max delay | `00 00` | `00 03` |
| 72-73 | terminator | `00 00` | `00 00` |

**The frame is complete and correct**: four TLVs at the right offsets with the
right types and lengths, 124 bytes, structurally identical to the one frame on
this wire known to be acceptable to something.

**And the decisive row is the partner block.** Ours names the switch exactly —
system `08:bd:43:76:47:e1`, key 20, port 12, state `0x45`. The switch's is all
zeroes. This host hears the switch perfectly and echoes it back correctly; the
switch has never heard this host.

#### What is established, and what is not

Everything from `bin/ipd`'s buffer to the MAC's transmit counter is now verified
by measurement rather than by reading code: the frame's bytes, its length, the
descriptor's `BSIZE`, the completion write-back, the VSI counter, the MAC
counter, on four distinct MAC ports, with `QTX_CTL` ownership, `RDYList`, the
VLAN section and the malicious-driver record all read back off the device.

**Nothing this host emits is wrong.** Six hypotheses were raised and killed in
order — `QTX_CTL.PF_INDX`, the four descriptor checks behind `MAL_TYPE 21`, the
VLAN handling section, the single switch-element uplink, the frame header, the
frame's TLVs — each fitting the evidence before its boot.

What remains is the switch's configuration, or the physical host-to-switch
direction, and **neither can be read from this machine**. The next move needs
switch access or a capture on the wire. That is the honest end of this line of
work rather than a seventh hypothesis.

#### One defect the dump did find

Our actor state on the wire is `0x05`. `Bundle::arm` sets `State::TIMEOUT`, so it
should be `0x07`. `Machine::received` was copying the partner's `LACP_Timeout`
onto this station's own:

```rust
self.actor.state = if pdu.actor.state.has(State::TIMEOUT) { … } else { … };
```

Those are two different statements in 802.1AX. `Actor_State.LACP_Timeout` says
*what rate I want you to send at* — this station's administrative choice.
`Partner_Oper_Port_State.LACP_Timeout` is the partner's version of it and is
what drives **this** station's Periodic Transmission machine. The code
conflated them, so a switch running the slow rate silently erased a request this
system had made. It is not the cause of `Defaulted`; it is the fifteenth
mechanism in this work set and then not present where it was supposed to take
effect.

`Machine::interval` now reads the partner's bit, and this station's own survives
what the partner says.

**And it nearly shipped a regression.** The first version defaulted a port that
has heard no partner to the *slow* rate. The code being replaced read this
station's own bit, which `Bundle::arm` sets, so an un-partnered port sent every
second; separating the two bits without deciding what a defaulted partner means
turned that into thirty — three PDUs in a ninety-second window where there had
been eleven, on the one measurement this work rests on. A silent link is exactly
the link that must keep speaking, so a defaulted partner gets the fast rate, and
the test says so.

**The covering test enforced the bug.** `the_partner_chooses_how_often_this_port_speaks`
asserted `machine.actor.state.interval_seconds()` — reading *this* station's bit
to discover what the partner had asked for, which is only a correct reading if
something copies one onto the other. Something did. The test named the right
behaviour and measured the mechanism instead, and it passed for as long as the
defect existed. It now asserts the interval through `should_send`, and that the
actor's own bit survives; watched red against the exact code it replaced.


### The timeout fix, confirmed on the wire — 2026-09-12

```
lacpdu sent   32: 07 00 00 00 02 14 80 00 08 bd 43 76 47 e1 00 14
lacpdu sent   48: 00 80 00 0b 45 00 00 00 03 10 00 00 00 00 00 00
ipd lacp       state 0x07 -- per link: link 0 0x07, link 1 0x07, link 2 0x07, link 3 0x07
```

Byte 32 reads `07` where it read `05`. The short timeout `Bundle::arm` asks for
now survives contact with a switch running the slow rate, instead of being
erased by every PDU that switch sends.

**LACP still has not aggregated, which is what was said before the boot.** The
switch's partner block is unchanged — all zeroes from offset 38 on — so it has
still never received anything from this host, and neither this station's own
timeout bit nor its transmit rate could change that. Recording it here because a
fix that lands and changes nothing about the symptom is worth stating as
plainly as one that does.

Our frame remains correct and complete: partner TLV `02 14` at 36 with the
switch's real identity echoed back (`08 bd 43 76 47 e1`, key `00 14`, port
`00 0b`, state `45`), collector `03 10` at 56, terminator at 72.

The position is unchanged from the conclusion above: everything this host emits
is verified correct by measurement, and the remaining variable cannot be read
from this machine.


### The switch has been saying where to find it — 2026-09-12

Asked to check the switch's configuration for those ports, the honest first
answer is that there are no credentials and no management address for it. What
*is* known about that configuration comes off the wire and is all measured:

| | |
|---|---|
| ports | `xg12`, `xg11`, `xg10`, `xg9` — LLDP port id subtype 7, locally assigned |
| system id | `08:bd:43:76:47:e1`, priority `0x8000` |
| LACP mode | **active** — it speaks first and unprompted |
| key | 20, identical on all four, so they are one channel-group |
| its actor state | `0x45` — Activity, Aggregation, **Defaulted** |
| its partner record | all zeroes: it has never received an LACPDU from here |
| collector max delay | 3 |
| LLDP | nine TLVs, **zero organizationally specific** |

That last row is why the wire cannot answer the question directly: a switch
normally advertises port VLAN id and link-aggregation status as
organizationally specific TLVs, and this one sends none.

**But it sends nine TLVs and `net/src/lldp.rs` decodes four** — chassis id,
port id, TTL and organizationally specific. IEEE 802.1AB types 4 to 8 are Port
Description, System Name, System Description, System Capabilities and
**Management Address**. The switch has been announcing its name and the address
of its own management agent on every frame, on all four links, since the first
boot that received one, and both were dropped.

Six hypotheses were raised and killed about a host that turns out to emit
correct frames, while the one machine whose configuration could not be read was
saying on every frame where to go and look. That is the fourth mechanism of this
kind in this work: a fact arriving on the wire and being discarded by the code
that walks past it.

So `SYSTEM_NAME` and `MANAGEMENT_ADDRESS` are parsed now and published at
`bin/ipd`'s report words 48 and 49, with the kernel printing an IPv4 address as
a quad and naming any other family rather than pretending it is one. This host
already routes to `10.5.5.0/24` — it reaches the BMC at `10.5.5.103` — so an
address on that network stands a fair chance of being reachable from here.

**The off-by-one this could have had.** The management address string length
counts the family octet *with* the address, so reading the address from byte 1
rather than byte 2 yields a plausible, wrong address rather than an error. The
test pins it and was watched red against exactly that.

**And a duplication found on the way.** `bin/ipd` builds its report in two
places — `refresh` and `report` — as two hand-written arrays that must agree
slot for slot, with nothing checking that they do. The length assertion catches
a missing word only because both feed the same `write_report`; two arrays of the
right length carrying different things in the same slot would pass it. Both are
updated here, and the hazard is written down where the second one lives.


### The neighbour, named — 2026-09-12

```
lldp neighbour reachable at 10.5.5.246
lldp neighbour calls itself "PRD-SW1"
```

It answers: 1.7 ms round trip from the build host, 0% loss, **port 80 open** and
22, 23 and 443 silent. The page it serves identifies it as a **NETGEAR XS716T**,
a sixteen-port 10G smart-managed switch, and asks for a login — so its
configuration needs credentials this work does not have, and guessing them is
not on the table for a switch named `PRD`.

Both facts had been on the wire since the first boot that received an LLDPDU.

**What only the switch can answer, and the screen that answers it.** Our
LACPDUs demonstrably leave four distinct MAC ports — 21/21, 11/11, 11/11, 11/11
out of each VSI and each MAC. The switch's own receive counters for ports 9-12
decide between three different faults, and nothing on this side can:

| reading | meaning |
|---|---|
| RX packets climbing | the frames arrive and its LACP rejects them — a configuration question |
| RX flat, CRC/FCS errors climbing | the frames arrive **damaged** — correct in the buffer the device reads, wrong on the wire |
| RX flat, no errors | they never arrive at all |

The error counter is the sharp one, because this work has already proven the
frame correct in memory: *arrived broken* would point at the physical layer and
at nothing in this repository.

And beside it, the same ports' **TX** counters. This host receives 11 to 15
LACPDUs per ninety-second window, so TX should be climbing. TX climbing while RX
stays flat is a one-way link, which is exactly what *"it is talking and not
listening"* looks like from this end.


### The switch answered it — 2026-09-12

`PRD-SW1`'s port statistics for ports 9-12: **received-without-error flat, CRC
errors climbing.** Every frame this host sends arrives damaged, is discarded at
the switch's MAC, and never reaches its LACP machine — which is exactly why its
partner record has been all zeroes while it transmits happily.

It also retires a loose end this document flagged and called half-circular.
Nothing this host transmits has ever been answered — no DHCP, no ARP, no TCP —
and that was attributed to an unbundled channel-group port suspending data
forwarding. It was not. Every frame is corrupt, so nothing could ever answer any
of it.

**A hundred percent failure is not a cabling signature.** Marginal copper gives
intermittent errors and the occasional good frame, and one good LACPDU would
have been enough for the switch to record a partner. Every frame bad, the same
way, on four ports at once is systematic. The BMC reports all four links up at
**1000 Mbps** on 10G ports into a 10GBASE-T switch, which is worth someone's
attention on its own — but a link that negotiated down is a *stable* link, and
it does not explain a total failure.

So it is the one thing all four ports share: how this driver tells the MAC to
build a frame.

§38.21.4.1.1: the controller *"calculates and inserts the Ethernet CRC for all
packets transmitted to the network according to a per port setting configured by
setting the CRC Enable bit of the Set MAC Config Admin Queue command"*.
Table 38-56 byte 2 bit 2: *"set to 1b to enable the MAC to append the CRC on
transmit. Set to 0b if software appends the CRC."*

**This driver has never issued that command.** Opcode `0x0603` was not in its
opcode list. With the bit clear, the MAC transmits exactly the bytes it is
handed and the receiver reads the last four of them — an LACPDU's trailing zero
padding — as the frame check sequence. Wrong on every frame, on every port, for
ever, while every counter on this side still says the frame left.

§38.10.6.8 says *"the default value is set for the MAC to append the CRC"*, and
that is worth stating against the hypothesis rather than hiding: on a fresh
device the bit should already be set. It describes a device that has not been
configured by somebody else, and this card ran PXE first. Either way the
correction is the same, and it is this work's recurring lesson for the third
time: **a driver asserts the MAC configuration it depends on rather than
inheriting it**, as `RDYList` and `GLLAN_TXPRE_QDIS` both had to learn.

`Set MAC Config` is sent at bring-up with the port's own frame size — read from
`Get Link Status` a line above, so the command states the one thing it is for
instead of resetting the MTU on the way past — and its answer is published
rather than discarded.

**And two counters that were already read and never shown**, because the next
boot has to be able to tell a bad transmit from a bad cable:

* `GLPRT_CRCERRS`, **this side's own receive CRC errors**, read into
  `PortCounters` since the counters were written and used only inside a boolean
  *is this wire live* test. If frames arrive here intact while ours arrive there
  broken, the damage is one-way and belongs to this side's transmit.
* The **link speed**, which `bin/netd` has published since links were read and
  this kernel has never printed.

That makes seventeen mechanisms in this work written, read or published and then
not acted on — and this one is a new kind again: not a value ignored, but a
command never sent at all.


### It was the CRC — 2026-09-12

> **Retracted the same day. The heading is left standing because the claim was
> published under it, and a correction that hides what it corrects is not one.**
> See *The reading was ambiguous* below: the switch counters this rests on were
> read while the SR550 was running **its own OS**, not Bhaskix, and the next
> boot showed the switch still `Defaulted` with an all-zero partner record.

`PRD-SW1`, after the boot that sends `Set MAC Config`: **CRC errors stopped,
received-without-error climbing.** The frames arrive intact.

And this side said the same thing from the other direction, on the same boot:

```
per member, link / our own rx crc errors: member 0 speed 4 crc 0 mac-config taken;
  member 1 speed 4 crc 0 mac-config taken; member 2 ... ; member 3 ...
nothing arrives here damaged, so a switch seeing every frame fail CRC is being
sent them broken -- one-way, and this side's
```

Our own `GLPRT_CRCERRS` is zero on all four ports: everything the switch sends
arrives here intact, so the wire was never the problem in either direction. The
damage was one-way and it was ours. (`speed 4` is `I40E_LINK_SPEED_1GB`, which
agrees with the BMC's 1000 Mbps — two independent sources for a reading this
document had only from one.)

**The datasheet was wrong about this card.** §38.10.6.8 says *"the default value
is set for the MAC to append the CRC"*, and that was stated plainly against the
hypothesis before the boot rather than hidden. It is not what this device came
up in: PXE firmware left `CRC Enable` clear, and because this driver had never
issued `Set MAC Config` at all, every frame it transmitted went out with four
bytes of its own payload where the frame check sequence belonged. A documented
default describes a device nobody else configured.

**Two real defects, and neither alone would have worked.**

1. **`RDYList` hardcoded to zero.** Three of four transmit queues were in an
   arbitration queue set that was not their function's, were never scheduled,
   and so never had their descriptors fetched. Uplink posts never written back
   went from 30-of-40 to 0-of-36 when it was fixed.
2. **`CRC Enable` never asserted.** Everything that *did* transmit arrived
   corrupt and was discarded at the receiver's MAC.

The first made three quarters of the frames never leave. The second made the
remaining quarter arrive broken. Fixing either alone would have changed nothing
observable at the far end, which is why the symptom was stable across every
boot for days while two independent faults sat behind it.

**What this retires.** Every LACP hypothesis in this document was downstream of
a frame that could not survive the wire: the switch's `Defaulted` state, its
all-zero partner record, `key 0, port 0`, and the observation that nothing this
host transmits has ever been answered by anything. None of it was a protocol
question. The protocol was correct throughout, and the whole-frame dump proved
it byte for byte before the cause was found.

**The lesson, for the third time and now the most expensive.** `FIRSTQ`,
`GLLAN_TXPRE_QDIS`, `RDYList` and now `CRC Enable` were all left as somebody
else had them, and three of the four were invisible on function 0 or on a
datasheet default. A driver asserts the configuration it depends on. It does not
inherit it and hope.


### The reading was ambiguous — 2026-09-12

The boot after `Set MAC Config` shipped:

```
ipd lacp       36 LACPDU(s) sent, 16 slow-protocol frame(s) heard back
per member, link / our own rx crc errors: member 0 speed 4 crc 0 mac-config taken; ...
ipd lacp       state 0x07 -- a partner is heard but the link is not yet aggregated
the partner says: link 0 0x45, link 1 0x45, link 2 0x45, link 3 0x45
and records its partner as key 0, port 0
```

`0x45` still carries **Defaulted**, and the switch's partner record is still all
zeroes. Had our LACPDUs arrived intact during this boot, its receive machine
would have recorded us within one exchange. It did not.

**So the previous section's conclusion does not follow, and the fault is in how
it was accepted rather than in the report that produced it.** Every boot in this
work ends with a `ForceRestart` back onto the SR550's own OS, which brings those
four ports up with a working driver and sends ordinary traffic. *CRC errors
stopped and received-without-error climbing* is exactly what that looks like too.
The boot being credited ended around 08:03 UTC and the machine had been running
its own OS ever since.

The counters were real. What they were counting was not established, and the
claim was published anyway — the same mistake as reading `FLAGGED` off a
malicious-driver register that had never been cleared, and for the same reason:
a plausible reading treated as a confirmed one because it agreed with the
hypothesis in hand.

**What settles it** is a reading taken *around* a single boot rather than after
one: the switch's counters for ports 9-12 immediately before the machine is
restarted onto Bhaskix, and again while it sits in the boot report. This host
sends about 36 LACPDUs in that window. Received-without-error rising by roughly
36 with CRC flat is the fix working; CRC rising by 36 with received flat is not.

**And what remains possible either way.** `mac-config taken` says firmware
returned success for `Set MAC Config`; it does not say the bit changed the MAC's
behaviour. That distinction has already cost this work once, when
`allow_destination_override` returned `Ok` and the flag had to be read back off
the VSI to show it had stuck. There is no `Get MAC Config`, so the switch's
counters are the only read-back that exists for this one.
