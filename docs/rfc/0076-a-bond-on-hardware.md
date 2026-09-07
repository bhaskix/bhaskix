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

### Two ports, and two is not a preference

Each X722 port costs one DMA window, four memory objects and **37 register
pages** — 42 capability slots. `cap::CSPACE_SLOTS` is 128 and the net domain's
first sixteen are spoken for, so:

| ports | slots | fits |
|---|---|---|
| 1 | 42 | yes |
| 2 | 84 | yes |
| 3 | 126 | no — nothing left for the rings, the report or `bin/ipd`'s ring |

**Two is what the capability space affords**, and a bond needs exactly two.
Three ports would need a larger cspace or a register window granted as something
other than one frame per page, and neither is worth doing for a member that adds
nothing to the gate.

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
