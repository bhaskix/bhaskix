# RFC 0011: `IrqHandler` — who may receive an interrupt

| | |
|---|---|
| **Status** | **Draft — for discussion.** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`cap`, `irq`, `trap`), arch (`ioapic`, `pci`) |
| **Milestone** | Phase 2 — with the driver framework |
| **Depends on** | [RFC 0010](0010-notifications.md) (the delivery mechanism), [driver-model.md](../driver-model.md) §2, [security.md](../security.md) §2 |
| **Blocked by** | An IOMMU. See *The prerequisite this RFC does not remove* |

---

## Summary

Two new object kinds. **`IrqControl`** — one privileged capability, held by
the initial domain, whose only method hands out the second. **`IrqHandler`** —
a capability naming exactly one interrupt source, with three methods: bind a
notification to it, acknowledge, and release.

[RFC 0010](0010-notifications.md) built *how* an interrupt reaches a thread.
This is *who may receive one*, which is a different question with a different
answer: an interrupt line is a hardware resource, claiming it excludes
everyone else, and some lines must never be claimable at all.

The kernel's interrupt path becomes: **mask the source, signal a notification,
acknowledge the controller.** Nothing else, ever, in interrupt context — which
is what [driver-model.md](../driver-model.md) §2 already promised and could
not deliver.

---

## Motivation

**1. `driver-model.md` names a type that does not exist.** §2 lists
`IrqCapability` as one of three types that "are the only types through which a
driver reaches hardware", and §2's *Why IRQ handling is not in interrupt
context* describes the nucleus path as "acknowledge the interrupt controller
and signal the waiting driver task". Both have been unfunded since they were
written. This RFC funds them.

**2. Every vector in this kernel is a constant in a different file.** M6-04
routed the serial line by hand: `SERIAL_VECTOR` in `input.rs`, an arm in
`trap.rs`, a call to `irq::route_isa` in `lib.rs`. The timer, the reschedule
IPI and the shootdown IPI each did the same. There is no allocator, so there
is no way to give a vector to anything, and no way to notice a collision
except by the machine behaving strangely.

**3. `virtio-blk` polls.** M6-06 spins on the used ring for the duration of
every request, and TRACKER records why: no object means "wake this thread when
that device fires". With RFC 0010 there is a way to wake a thread; there is
still no way to say *which* device may wake it.

---

## The prerequisite this RFC does not remove

**A user-mode driver needs an IOMMU, and this RFC does not provide one.**

Without one, a device programmed by a domain can read and write all of
physical memory by DMA, whatever the interrupt design says. Giving a domain a
device is giving it the machine. `memory.md` §5 says as much, and since RFC
0009 the kernel prints it at boot.

So the honest statement of what this RFC delivers:

| | Status after this RFC |
|---|---|
| An in-nucleus driver stops polling and waits on an interrupt | ✅ Available |
| Interrupt authority is an object that can be delegated | ✅ Available |
| A driver **in a domain** can be given a device safely | ❌ Still needs an IOMMU |

That is not a reason to defer this work. The interrupt half is useful on its
own — it is what lets `virtio-blk` stop burning a CPU — and building it now
means the IOMMU RFC is about memory rather than about memory *and* interrupts.

---

## Design

### Two objects, because there are two questions

```rust
/// The right to hand out interrupt sources. One, held by the initial domain.
pub struct IrqControl;

/// The right to receive one interrupt source.
pub struct IrqHandler {
    source: Source,               // a GSI, or an MSI-X entry of a PCI function
    vector: u8,                   // allocated by the kernel; never told to anyone
    notification: Option<(NotificationId, u64)>,   // where to signal, with what badge
    masked: bool,                 // set on delivery, cleared by ACK
    owner: DomainId,
}

pub enum Source {
    /// A legacy line, routed through the I/O APIC.
    Line { gsi: u32 },
    /// One entry of a PCI function's MSI-X table.
    MessageSignalled { device: pci::Address, entry: u16 },
}
```

| Capability | Method | Effect |
|---|---|---|
| `IrqControl` | `CLAIM(source)` | Allocate a vector, program the controller, return an `IrqHandler` capability |
| `IrqHandler` | `BIND(notification)` | Signal that notification when this source fires |
| `IrqHandler` | `ACK` | Unmask the source; the next interrupt may be delivered |
| `IrqHandler` | `RELEASE` | Mask permanently, free the vector, release the claim |

Destroying the capability is `RELEASE`. Destroying the owning domain is
`RELEASE` for every handler it held — a domain that dies mid-request must not
leave a line masked for the life of the machine.

### The vector is never named outside the kernel

`CLAIM` allocates a vector and does not report it. A domain that could choose
its vector could choose the timer's, and a domain that could *learn* one has
learnt a number that is only useful for guessing at others.

This means the kernel needs a real vector allocator, which it does not have:

```rust
pub struct Vectors {
    /// One bit per vector. 0..32 are the CPU's exceptions and are never free.
    free: [u64; 4],
}
```

**The kernel's own vectors are claimed from the same allocator at boot**, so
there is one source of truth instead of five constants in four files. That is
a cleanup M6-04 deferred and this RFC pays for: the timer, the reschedule IPI,
the shootdown IPI and the serial line all become allocations, and a collision
becomes a failure at boot instead of a machine that behaves strangely.

### Claiming is exclusive, and some sources cannot be claimed

Two rules the allocator enforces, both of them checkable rather than
conventional:

1. **A source may be claimed once.** A second `CLAIM` of the same source is
   refused while the first handler exists. Without this, two domains bind two
   notifications to one line and each sees half the interrupts.
2. **Reserved sources are never claimable.** The timer and the two IPIs are
   the kernel's; `CLAIM` refuses them by name, not by their vector, so the
   refusal survives the allocator moving them.

### Only message-signalled sources may be claimed by a domain

A legacy PCI `INTx` line is *shared* — several functions raise the same line,
and the handler must ask each of them whether it was theirs. That interacts
badly with an untrusted holder in a way that has no good fix:

- The kernel masks the line on delivery and unmasks on `ACK`. A domain that
  never acknowledges masks a line **that other devices are using**.
- The kernel cannot ask the other devices on the driver's behalf without a
  driver for each of them.

So: **a domain may claim only `MessageSignalled` sources.** An MSI-X entry is
not shared with anyone by construction, so a driver that never acknowledges
harms only itself. Legacy lines remain claimable by in-nucleus code, which is
what the console and the timer are.

This is a real restriction and it costs almost nothing: every device that
would plausibly be driven from a domain — NVMe, virtio, xHCI, modern NICs —
supports MSI-X, and `driver-model.md`'s own manifest example already writes
`irqs = { kind = "msix", max = 64 }`.

### MSI-X is programmed by the kernel and never delegated

An MSI is a **memory write the device performs**: an address in the local APIC
window and a data word that *is* the vector. A holder that could program it
could point any device's interrupt at any vector on any CPU — a general
interrupt-injection primitive, obtained by writing two words.

Therefore the kernel programs the MSI-X table entry, and the domain never gets
a mapping of it. Concretely, `CLAIM` on a `MessageSignalled` source:

1. finds the MSI-X capability in the function's configuration space,
2. maps the table BAR **in the kernel**,
3. writes address `0xfee0_0000 | (apic_id << 12)` and data `vector`,
4. clears the entry's mask bit and sets MSI-X Enable in message control,
5. sets `INTERRUPT_DISABLE` in the command register, so the same device cannot
   also raise a legacy line.

A domain granted an `MmioCapability` for the device's BARs must therefore be
granted one that **excludes the MSI-X table's pages**. That is a real
constraint on whatever hands out MMIO capabilities, and it is written here
because the place it will be got wrong is there.

### The interrupt path

```
handle_interrupt(vector):
    handler = claims[vector]            ← published Release, read Acquire
    if handler is none:
        count a stray; end_of_interrupt(); return
    mask(handler.source)                ← I/O APIC entry, or MSI-X vector control
    signal(handler.notification)        ← RFC 0010: two atomics and a wake
    end_of_interrupt()
```

Three properties, each load-bearing:

- **Mask before signal.** A level-triggered line that is not masked re-asserts
  the instant the handler returns, and the CPU spends its life in the handler.
  Masking is also flow control: a driver that is slow gets fewer interrupts
  rather than a storm.
- **Nothing here takes a lock.** The claim table is an array indexed by vector,
  written under a lock at `CLAIM` time and read atomically in the handler.
  `signal` is lock-free by RFC 0010's design, which was chosen for exactly
  this caller.
- **Acknowledge the controller last**, as `trap.rs` already does everywhere,
  because an unacknowledged interrupt blocks every later one.

### Acknowledge, and the edge that is lost while masked

`ACK` unmasks. Between delivery and `ACK` the source is masked, and what
happens to an interrupt raised in that window depends on the source:

| Source | An event while masked |
|---|---|
| Level-triggered line | The controller holds the level; delivered on unmask |
| Edge-triggered, or MSI | **Lost** |

So the rule for driver authors, which belongs in `driver-model.md` when this
lands: **drain the device before acknowledging.** Read the device's completion
state until it is empty, *then* `ACK`. A driver that acknowledges first and
reads second will one day sleep with a completion sitting in a queue and no
interrupt coming, and that bug will present as a hang under load and nothing
at all in testing.

### Which CPU receives it

The kernel decides, and the first version decides simply: the CPU the bound
notification's waiter was last on, and the bootstrap CPU if there is none.
Interrupt affinity that follows a thread as it migrates is an optimisation
with a measurement attached, and it is not this RFC.

What matters for `scheduler.md` §4 is that a driver woken by an interrupt is
an ordinary RT wake-up: the p99.9 target of 50 µs applies to it, measured
from `signal` to the waiter running, and the gate for it already exists.

### Concurrency

| Path | Locks | Context |
|---|---|---|
| `CLAIM` / `RELEASE` | vector allocator, then the controller | thread |
| `BIND` | the handler's arena entry | thread |
| `ACK` | none beyond the controller write | thread |
| delivery | none | interrupt |

The controller writes — an I/O APIC redirection entry, an MSI-X vector control
word — are the same index/data and MMIO accesses M6-04 and M6-06 already make,
and carry the same rule: programmed on one CPU, at claim time, never
concurrently.

### Failure behaviour

| Situation | Answer |
|---|---|
| Source already claimed | Refused; the first holder keeps it |
| Reserved source | Refused by name |
| No free vector | `QuotaExceeded`; nothing is programmed |
| `ACK` with nothing masked | Accepted and ignored; it is not an error to be early |
| `BIND` to a revoked notification | Refused at bind; a revoked notification after bind makes the signal a no-op, counted |
| Domain dies holding a handler | `RELEASE`: source masked, vector freed, claim released |
| Interrupt on an unclaimed vector | Counted as a stray and reported, as `trap.rs` already does |
| Device raises continuously and the driver never acks | The source stays masked. With MSI-X that harms only this device |

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **No `IrqControl`; any domain may claim any line** | Ambient authority over the interrupt space. A domain claiming the timer stops the machine. | Never. |
| **Tie claiming to a device object instead** — you may claim the interrupt of a device you hold | This is the *right* answer and it needs a PCI device object, which is the driver framework. Exclusive claiming gets most of the safety now, and this RFC says plainly that the device-object form supersedes it. | This is the destination, not a rejection. It arrives with the driver framework. |
| **Let the driver program its own MSI-X** | An MSI is a device write of an arbitrary vector to an arbitrary CPU. Delegating it is delegating interrupt injection. | Never without an IOMMU that constrains where the device may write — and even then, no. |
| **Allow domains to claim shared `INTx` lines** | A holder that never acknowledges masks a line other devices need, and the kernel cannot poll those devices for it. | If a workload needs a domain to drive a device with no MSI-X, and accepts that the line is then that domain's to wedge. |
| **Deliver into the driver's thread as an upcall** | Interrupt context in a domain: a stack that was in use, a handler that must be reentrancy-safe, and `driver-model.md` §2's whole argument against it. | Never. The split is mandatory on purpose. |
| **Keep the hand-routed constants and add a claim table beside them** | Two sources of truth for what owns a vector, and the first collision is a machine behaving strangely rather than a boot failure. | No — the allocator is most of the value. |
| **Poll** (the status quo) | A CPU per outstanding request, and no path to a driver in a domain. | — |

---

## Impact on existing design documents

**[driver-model.md](../driver-model.md) §2** lists `IrqCapability` as one of
the three types a driver reaches hardware through. This RFC makes it concrete
and renames it `IrqHandler` for consistency with the object it names; the doc
should follow. §2's *"the nucleus IRQ path does exactly one thing: acknowledge
the interrupt controller and signal the waiting driver task"* becomes exactly
true, with one addition it does not mention and needs: **it masks first.**

That doc also needs the drain-before-ack rule, in §2, next to the sentence
about not running in interrupt context — because that is where a driver author
will be reading when they get it wrong.

**[memory.md](../memory.md) §5** is unchanged and its warning becomes sharper:
this RFC hands out interrupts but not devices, and the reason is written into
*The prerequisite this RFC does not remove*.

**[scheduler.md](../scheduler.md) §4** gains a new source of RT wake-ups. The
50 µs p99.9 target applies unchanged; what changes is that it now has a
hardware-triggered case to measure, which is the more interesting one.

**No existing document becomes wrong.** Two become true.

---

## Security implications

**New authority.** Receiving an interrupt, delegable exactly once per source.
`IrqControl` is the privileged root of it and is held by the initial domain —
it is the kind of capability that should appear in an attestation log, and
`docs/security.md` should say so.

**What becomes reachable without a capability.** Nothing. Claiming needs
`IrqControl`; receiving needs an `IrqHandler`; being woken needs a
notification the holder bound.

**Denial of service.** Bounded to the claiming domain by the MSI-X-only rule:
a handler that never acknowledges masks its own device's interrupts and
nothing else's. Vectors are a global resource of 224, so `CLAIM` is charged
against the domain's capability quota — otherwise a domain claiming in a loop
exhausts the vector space, which is T10 through a door nobody was watching,
the same one M5-06 closed for capabilities.

**The interrupt-injection primitive, and where it is kept.** Programming an
MSI is equivalent to injecting an arbitrary interrupt on an arbitrary CPU.
This RFC keeps that in the kernel and states the consequence for whoever hands
out MMIO capabilities: **a device's MSI-X table pages must never be inside an
`MmioCapability` given to a domain.** If that is got wrong, everything else
here is decoration.

**New parser for untrusted input?** The MSI-X capability structure, read out
of a device's configuration space — which is a device the kernel already
trusts enough to drive. It is a fixed-layout structure with two bounded fields
(a BAR index and an offset), both range-checked, and it joins the PCI
capability walk that M6-06 already bounds against cycles. No new fuzz target;
the values are checked at their use.

---

## Performance implications

**Faster:** `virtio-blk` stops spinning. The measurement is direct and
assertable rather than statistical — the driver currently counts its poll
iterations, and with an interrupt that count is zero.

**Slower:** a claim, once, at driver start.

**What will be measured:**

| Measurement | Today |
|---|---|
| Poll iterations per block request | thousands |
| `signal`-to-waiter-running, p50 and p99.9 | n/a; the path does not exist |
| Interrupts delivered per request | 0 |
| Time in interrupt context per delivery | n/a — target: bounded, tens of instructions |

The third is the one that catches a mistake nobody expects: a level-triggered
line that is not masked delivers thousands of interrupts per request rather
than one, and the count says so immediately.

---

## Testing plan

**On the host:**

- The vector allocator: exhaustive over the range; reserved vectors refused;
  a claim followed by a release makes the vector available again; exhaustion
  reported rather than wrapping.
- Exclusive claiming: the second claim of a source is refused, and the first
  holder is unaffected.
- The source table's publish/read ordering, as a model — a handler read
  concurrently with a claim sees either the old entry or the new one, never
  half of each.

**In QEMU:**

- **Dogfood first.** The serial line is claimed through `IrqControl` by the
  kernel itself, bound to a notification, and `input.rs` reads from it. The
  console still works, which is a strong end-to-end assertion because every
  other test types at it.
- `virtio-blk` on MSI-X: a block request completes with **zero** poll
  iterations and exactly one interrupt. Both are counters that already exist.
- A never-acknowledging handler receives exactly one interrupt, and the device
  it belongs to is the only thing affected.
- Domain teardown while a handler is claimed: the vector is freed and the
  source is masked, asserted by claiming it again afterwards.

**Negative tests** (each must fail its gate when introduced):

- Signal without masking → the interrupt count per request goes from one to
  thousands.
- Acknowledge before draining → a completion is missed under load, which the
  ring test surfaces as a stall rather than as slowness.
- A reserved source claimable → the timer can be taken, and the machine stops.

**On real hardware:** this is the first thing in the project whose behaviour
plausibly differs on real hardware — level triggering, shared lines, and
firmware that has already programmed things. M1-17's hardware boot gains a
reason beyond "does it boot".

---

## Unresolved questions

1. **Interrupt affinity.** The first version pins delivery to one CPU. Whether
   it should follow the waiting thread, and what that costs in reprogramming
   the controller, is a measurement nobody has taken.
2. **Should `IrqControl` be global, or one per bus?** Global is simpler and
   makes the initial domain a single point of authority. Per-bus would let a
   bus be delegated whole, which is what a VM would want.
3. **What happens when a device raises an interrupt on a source whose holder
   has died?** Proposal: masked permanently at `RELEASE`, and reported. The
   alternative — leaving it unmasked and letting it become a stray — turns a
   dead driver into a machine-wide interrupt storm.
4. **MSI (not -X).** Older devices have MSI with up to 32 vectors and a
   different programming model. Proposal: MSI-X only, and legacy lines for
   everything else, until a device needs otherwise.
5. **Interrupt coalescing and thresholds** are device policy, not kernel
   policy — but a driver in a domain has no way to say "wake me at 32
   completions" except through its own device. Recorded because it will come
   up as a performance question.

---

## Implementation plan

1. **The vector allocator**, with the kernel's own four vectors moved onto it.
   No new objects. This is a refactor whose success criterion is that every
   existing gate still passes and the vectors are now printed at boot.
2. **`IrqControl` and `IrqHandler` for legacy lines**, claimed by in-nucleus
   code only. `CLAIM`, `RELEASE`, exclusivity, reserved sources.
3. **`BIND` and the delivery path** — mask, signal, acknowledge — with
   `input.rs` moved onto it. The console keeps working, which every other test
   already checks.
4. **MSI-X programming**, kernel-side, and `virtio-blk` moved onto it. The
   poll-iteration counter goes to zero; the interrupt counter goes to one per
   request.
5. **Domain teardown**: release on death, with the re-claim test.
6. **Delegation to a domain** — the point of the whole exercise, and the step
   that must not be taken until there is an IOMMU. It is listed so that the
   sequence is written down, not so that it is scheduled.

Steps 1–4 are useful with no domain involved and pay for themselves in the
CPU `virtio-blk` stops burning. Step 6 is a different RFC's prerequisite away.
