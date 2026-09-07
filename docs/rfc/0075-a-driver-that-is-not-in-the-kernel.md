# RFC 0075: a driver that is not in the kernel

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / kernel |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0018](0018-networking.md), [RFC 0046](0046-a-disk-this-machine-has.md), [RFC 0072](0072-a-driver-for-the-nic-this-machine-has.md), [RFC 0074](0074-what-a-network-interface-is.md) |

---

## Summary

`kernel/src/i40e.rs` was three thousand lines of device driver **inside the
nucleus**, with another nineteen hundred of plumbing beside it. This moves the
driver out: into `i40e/`, a crate that forbids `unsafe`, reaches registers
through a trait its holder implements, and takes every ring and command buffer
as a slice.

It is the shape `ahci/` already has, for the same reasons and one more of its
own — the X722 is the only device this project drives whose driver could not be
tested at all.

## Motivation

**Every other driver in this tree is a service.** RFC 0018 put the network
driver in ring 3; RFC 0046 put the SATA driver there and split its register
arithmetic into `ahci/`, which is `#![forbid(unsafe_code)]` with forty-six host
tests. The X722 never got that treatment, and it has cost three things.

**The half that mattered had no tests.** Twelve tests covered the byte
encoders — descriptors, contexts, counters. Not one could reach a register,
because reaching one needed an address, and an address needed a machine. Every
bug this driver has actually had was in that half:

* a transmit tail written as a *count* rather than an index, which stopped the
  queue after four frames and lost forty-five LACPDUs (RFC 0073);
* two callers each keeping their own ring cursor, driving the tail backwards;
* five promiscuous flags bundled into one command firmware would only take one
  at a time.

Each was found by booting a particular server in a particular rack. Each is
arithmetic a host test can drive in a millisecond.

**It ran with the kernel's authority.** The driver mapped roughly four megabytes
of BAR0 through the direct map and dereferenced raw addresses, in the one
component whose whole purpose is to be small enough to reason about.

**And the SR550 cannot run the network stack.** `bin/netd` drives virtio and
nothing else, so on the only multi-port machine in the project the boot says
`net domain no device on the bus; nothing delegated`. RFC 0074's bonding and
LACP cannot reach hardware, and the reason is that the machine's NIC and the
service that could bond it are on opposite sides of a device class.

## Design

### The crate holds no address

```rust
pub trait Registers {
    fn read(&self, offset: u64) -> u32;
    fn write(&mut self, offset: u64, value: u32);
    fn read64(&self, offset: u64) -> u64;
}
```

`ahci/`'s trait with one addition: `read64`, because the statistics counters
say *"the low and high registers are part of a 64-bit register and are read
using 64-bit read accesses only"* and two 32-bit reads would tear across a
counter incrementing between them.

`Device<R: Registers>` holds the registers and its cursors and nothing else, so
**the one unsafe operation a NIC driver genuinely needs — a volatile access to a
mapping somebody else made — belongs to whoever owns the mapping.**
`forbid(unsafe_code)` makes that a rule rather than an intention.

### DMA memory is not a slice, and a boot is how that was learned

Rings and command buffers arrived as `&mut [u8]` first. It reads as the obvious
translation of a raw pointer and it is wrong: **a `&mut` promises the compiler
that nothing else writes those bytes, and a device writing them is precisely
something else.**

`Get Switch Configuration` zeroes its buffer, posts the command and reads the
buffer back. On the SR550 it read back the zeroes — forwarding them across an
opaque call is a legal thing to do to memory nobody else may touch — and the
boot said:

    nic switch     0 element(s) reported of 0 in the switch
    nic rx queue   not taken: no VSI was reported, so nothing would steer a frame to a queue

against `1 element(s) reported of 1` the run before. Registers were unaffected,
because those already went through a trait whose implementation is volatile.

So there is a second trait, and it is the same argument twice:

```rust
pub trait Dma {
    fn read(&self, at: usize, into: &mut [u8]);
    fn write(&mut self, at: usize, from: &[u8]);
    fn zero(&mut self, at: usize, bytes: usize);
}
```

The crate does the arithmetic and holds no address of either kind. **This is
worth more than the move itself**: `bin/ahcid` builds a `&[u8]` over
device-written memory today and has the same exposure, latent because it never
zeroes and re-reads through one live reference. The pattern now has a name and a
test.

### Passing the rings rather than holding them

The first version of this held `&mut [u8]` inside `Device`, which put one
argument in nine signatures instead of thirty. It was wrong, and the tests are
what said so: **a driver holding the ring cannot be handed a ring a test also
wants to write**, so firmware's half of a command round-trip could not be
modelled at all, and the command path stayed exactly as untestable as it had
been in the kernel.

So the rings are parameters, and `command` is split into `post` and `collect` —
a test posts, fills the descriptor the way firmware would, and collects. That
split is also what a service wants: a command outstanding while other work
happens.

### Which register pages a driver may reach

`cap::ObjectKind::Frame` is one page, and the X722's CSR space is just under
four megabytes — a thousand pages against a hundred and twenty-eight capability
slots. The whole BAR cannot be delegated, and it should not be: beyond the CSR
space are protocol-engine doorbells and an exposed flash.

So the crate exports `REGISTER_PAGES`: the **thirty-four** pages that contain a
register it names, each indexed register covered to the highest index the
datasheet allows, so a queue number the driver accepts can never land outside
the mapping. Two host tests keep the list and the constants from drifting —
one that every named register is inside a listed page, and one that every listed
page is reachable and that the flash beyond is not.

That is strictly *less* authority than the kernel had when it drove this itself.

### What stays in the kernel, for now

The kernel still drives the device at this step, through a three-line
`MappedRegisters` and one `device_bytes` that turns a direct-map address into
the slice a ring is. The report, the memory and the boot-time demonstration are
unchanged. **The machine must print the same lines after the move as before it**,
which is what makes the move provable on its own.

## Steps

**Step 1 — the crate.** Move the file, add `Registers`, make `Device` generic,
take the rings as slices, add the fake register file and the tests, export
`REGISTER_PAGES`.

> **Gate:** `cargo test --workspace` covers the crate, at least three of the new
> tests watched red, and an SR550 boot prints the report it printed before.

**Step 2 — the service side.** `bin/netd` gains an i40e back end: the
`Registers` impl over pages it was granted, the memory objects, bring-up, and
the report words.

> **Gate:** on a lane with no X722 it does nothing and says so — which every
> QEMU lane can check.

**Done 2026-09-07.** `bin/netd` implements both traits over pages and memory it
was granted, and `take_x722` asks the capability space whether there is a device
rather than being told: it attaches the register pages, and their absence is the
answer on every machine that has none. It brings the device up as far as RFC
0072 step 3 did — reset, admin queues, `Get Version`, `Get Link Status`, `Get
Switch Configuration` — and publishes what it found in report words 22 and 23.

The kernel prints that line only where there is something to say, and prints a
**warning where the bus has an X722 that `bin/netd` was not given**, which is the
state between this step and the next. All twenty-two lanes pass with the absence
path taken on every one of them.

**Step 3 — the delegation.** `start_net_domain` delegates the register pages,
the DMA window and the memory; it starts `bin/netd` when there is **any** port,
virtio or X722; the `nic` domain and `start_nic_domain` go.

> **Gate:** an SR550 boot shows the same `nic ...` lines, produced from ring 3.

**Step 4 — the plumbing goes.** The nineteen hundred lines in
`kernel/src/lib.rs` are deleted with the measurements they made moved into
report words.

> **Gate:** the kernel's unsafe budget, stated in the manifest, and a green suite.

## Alternatives considered

**A service of its own, `bin/i40ed`.** The obvious mirror of `bin/ahcid`, and
rejected for one reason: the bond lives inside `bin/netd`, so an X722 port could
not join it without an inter-service protocol that does not exist — and reaching
the bond is why this is being done at all. If the bond ever moves above the
drivers, this decision should be revisited.

**Leaving the driver in the kernel and adding tests there.** The tests are the
larger half of the value and could have been had without moving anything. It
was rejected because the tests that matter need a *fake device*, and a fake
device needs the trait — at which point the driver no longer needs to be in the
kernel, and staying there would only keep the authority.

**A multi-page window capability.** A `Frame` that named a run of pages would
make the register window one capability instead of thirty-four. It is a nucleus
change — capability semantics, revocation, mapping — and it is not this RFC's.
Thirty-four slots of a hundred and twenty-eight is affordable.

## Impact on existing design documents

`docs/architecture.md`'s driver model gains a third instance of the same shape;
nothing in it changes. `TRACKER.md` records the move. RFC 0072's steps are
unaffected — the driver it built is the driver that moved, and its unfinished
receive path is unfinished in exactly the same way.

## Security implications

**Authority goes down.** The driver reached four megabytes of MMIO through the
direct map with the kernel's rights; after step 3 it reaches thirty-four pages
it was granted, and cannot name anything else. Its rings are slices, so a
descriptor written past the end is a bounds check rather than a write into
whatever follows.

**And the blast radius of a bug in it shrinks from the nucleus to a domain**,
which is the argument RFC 0018 made for the network driver and RFC 0046 for the
disk. This is that argument's third application, on the driver that had the
weakest claim to an exemption and the strongest reason to be tested.

## Performance implications

A trait call per register access, which inlines: `Registers` has one
implementation in each binary. The slices add a bounds check per descriptor
word, against a device that answers in microseconds. Neither is measurable
against a PCIe round trip, and neither was measured — the honest statement is
that this change is not about speed.

## Testing plan

**Host tests are the point.** The crate carries twenty-three: the twelve encoder
tests that moved, and eleven new ones over the half that had none — the reset
handshake, the admin-queue enable order, a command posted and answered, a
refusal against silence, a command with no ring, the transmit cursor's wrap, an
uplink frame's two descriptors, the receive-queue handshake, the two that
keep `REGISTER_PAGES` honest, and the one that reads a buffer a device filled
rather than the zeroes that preceded it.

**Five of them watched red**: the cursor wrap (by removing it — the bug that
lost forty-five frames), the enable order (by writing the length first), the
no-ring refusal (by removing the guard), the register-page list (by dropping a
page from it), and the DMA read-back (by parsing zeroes instead of what the
device wrote — the regression above, now a test that fails in a millisecond
instead of a boot).

**And one SR550 boot per step that changes what the hardware does**, compared
line by line against the boot already captured. QEMU has no X722 and never will;
what the lanes prove is that a machine without one is unaffected.

## Unresolved questions

1. **Whether `bin/netd` should hold two device classes at all.** It is the right
   answer while the bond lives there. If the bond moves above the drivers — and
   there is an argument that it should, since a bond is not a property of a
   driver — then this becomes two services and an interface between them.
2. **What to do about the SR550's receive path.** RFC 0072 step 4 has never
   delivered a frame, and this changes nothing about that. What it changes is
   that the queue programming, the context encoding and the descriptor handling
   can now be exercised without the machine, which is where the next attempt
   should start.
