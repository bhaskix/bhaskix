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
