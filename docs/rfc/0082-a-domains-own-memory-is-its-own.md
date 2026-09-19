# RFC 0082: a domain's own memory is charged to its envelope

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-19 — all six steps built and gated; `make test` green on every lane, and the acceptance call is the project lead's.** A domain's own memory is charged to its envelope and refused past it, on three allocation paths. Six assertions, every one armed red before being believed. Two things the measurement changed are recorded in *What the boot measured* below, and one of them corrects this document's own argument. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`vm`, `domain`) |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (the object the envelope already bounds), [RFC 0017](0017-process-management.md) (the domain lifecycle); closes the open half of [security.md](../security.md) §1 **T10** |

---

## Summary

`ResourceEnvelope::memory_frames` is described as a hard cap on a domain's
memory and is not one. It bounds the frames a domain spends on *shared
objects* and nothing else: a domain's own address space — every page it maps,
every page a fault commits under it — is allocated without the envelope being
consulted. This charges those frames too, and does it from the page-fault
handler, which is the constraint that decides the whole design.

## Motivation

**The threat model already says this, and says it is open.**
[security.md](../security.md) §1 T10 — *resource exhaustion by one domain
denying service to others* — is marked 🔨 partial, and the note under the table
spells out which half:

> `domain::charge_frames` refuses past the cap, and its only real caller is
> `shared::create` — so the envelope bounds **shared objects** and not a
> domain's own address space: `map_anonymous` charges nothing and the fault
> path that commits a lazy reservation charges nothing. **A domain can exhaust
> memory past its envelope, which is this threat.**

Every clause of that was re-checked against the tree on 2026-09-19 and every
clause is true. `charge_frames` has exactly one real caller,
`kernel/src/shared.rs:302`. `AddressSpace::map_anonymous` allocates in a loop
straight from the physical allocator. `map_anonymous_lazy` inserts a region and
returns; the frames arrive later, in `service_fault`, from this CPU's reserve.
Nothing on any of those paths knows which domain it is spending for.

**So the cap is not a cap.** A domain holding nothing but a `DomainControl`
capability and an address space can map until the machine is out of frames. It
needs no capability it was not given and no bug to exploit: `map_anonymous_lazy`
over a large range, then touch it. The envelope refuses none of it, and the
only thing that eventually says no is the physical allocator, on behalf of
everybody.

**And the gate that reads as proof is the wrong shape.** The same note says so,
which is the more useful half of the problem:

> The boot gate behind T10 asserts a line the kernel prints after calling
> `domain::charge_frames` **directly** … That is a true and worthwhile test of
> the accounting function. It is not a test of the claim above it, which is
> that a domain's *allocations* are charged — and nothing in the tree connected
> the two, so the gate went green for a year while the property it was written
> to defend was false for every allocation path except one.

A mechanism gate passing while its property is absent is the failure this
project exists to refuse. Closing the hole without also replacing that gate
would leave the next reader in exactly the position this one was in.

## Design

### The constraint that decides everything

**The page-fault handler may not take a lock.** `service_fault` takes its frame
from `frames::take()` — a per-CPU reserve — and the comment at
`kernel/src/vm.rs:1135` says why: *"the allocator's lock is the one thing a
fault handler must never wait for: a fault can interrupt code on this very CPU
that already holds it, and then neither can proceed."* `SPACES` itself is
`try_lock`ed for the same reason, and the handler tells a self-deadlock from a
coincidental hold rather than dying on either.

`domain::charge_frames` goes through `TABLE.lock()` at `Rank::Domains`. It
cannot be called from there as it stands, and making the fault path block on
the domain table would reintroduce precisely the hang those two comments were
written about.

### The accounting comes out from behind the lock

`charged_frames` and the frame cap become two lock-free `AtomicU64` arrays
indexed by `DomainId`, which is the raw table index and bounded by
`MAX_DOMAINS`.

- **The cap has one writer.** It is published when the envelope is set, at
  `domain::create`, under the table lock that already serialises creation.
  Everything else reads it.
- **The charge is a compare-exchange loop** against that cap: it either lands
  entirely or refuses entirely, and it never exceeds. `release_frames` is a
  saturating subtract, for the reason its present doc comment gives — releasing
  more than was charged is a bug, and reporting zero beats wrapping to a number
  that reads as an enormous allocation.
- **`charge_frames` and `release_frames` keep their signatures**, so
  `shared.rs`'s four call sites and the existing host tests are untouched by
  the move.
- **A reused slot starts at zero.** The reset goes where `domain.rs` already
  zeroes `charged_frames` on reuse. A slot that inherited a charge would be the
  hazard RFC 0081 was rejected over, one field along.

### An address space knows whose it is

`AddressSpace` gains `owner: Option<DomainId>`, set in the two places that
already bind a space to a domain — `vm::register_for`, and `vm::install` where
it calls `domain::record_space_root`. Nowhere else, because those are the two
places that can honestly say whose the space is.

**`None` is the kernel's own**, and is charged nothing. It is the same `None`
that `sched::domain_of` already answers for a kernel thread, and the
self-tests — `demand_paging_self_test`, the frame-leak gate — build spaces no
domain owns.

**And a space is mapped before it is owned, which the first draft of this
design missed.** `started_program` maps a stack, loads an ELF, and only then
calls `install` — so an owner arriving at install time takes over a space that
already holds most of a program. `AddressSpace` therefore carries `charged`:
what it holds, whoever is paying. `own` releases that total from the previous
owner and hands it to the new one, and the hand-over does **not** consult the
cap — the frames exist and are that domain's, and declining to count them
because they overflow would be this RFC's own hole with a different name. A
domain that lands over its cap is refused its *next* allocation, which is the
enforcement working rather than failing.

### The invariant

> **A domain is charged for every frame its address space holds, and for
> exactly those.**

Which fixes where the code goes without further argument: charge where a frame
enters a space, release where one leaves.

| Path | What it does |
|---|---|
| `AddressSpace::map_anonymous` | charges the whole range before allocating; releases it all if any page fails, because the unwind leaves nothing mapped |
| `AddressSpace::map_anonymous_lazy` | charges nothing — it maps nothing |
| `service_fault`, demand-paging arm | charges one, before taking a frame from the reserve |
| `service_fault`, copy-on-write arm | charges one: the copy is a new frame, and the original is deliberately not freed |
| `unmap`, `unmap_pages`, `destroy` | release exactly the number of frames actually freed, which is not always the number asked for |
| `own` | transfers what the space already holds from the old owner to the new, past the cap if need be |
| `map_shared` | charges nothing — the frames belong to a `Memory` object and were charged to its owner at `shared::create` |
| `map_device` | charges nothing — MMIO is not frames |

### Failure behaviour

**A refused eager mapping** returns `VmError::MemoryEnvelopeExceeded` with
nothing mapped and nothing taken, which is the contract `map_anonymous` already
keeps for every other error.

**A refused fault** returns `FaultOutcome::Refused("the domain's memory
envelope is full")`. `kernel/src/trap.rs:259` already turns a `Refused` into a
named diagnostic, and the program ends — the same shape as an access to a guard
page. For a hosted Linux process it takes the same crossing to the personality
that any other fault takes, so `bin/linuxd` decides what the program is told;
the nucleus does not invent a signal.

**A charge has a second error and it gets a second message.** A space whose
owning domain has *ended* answers `NoSuchDomain`, and that is refused as *"the
domain that owns this address space has ended"*. Two diagnoses pointing at
different halves of the system; reporting the second as the first is the
mistake `TRACKER.md` records as *a gate naming a cause it had not measured*,
four times over. It ought to be unreachable — `domain::end` calls `vm::forget`,
and a space outside the table never reaches the handler — and "ought to be
unreachable" is why it is named rather than why it is not.

That is a deliberate choice of *refuse the domain* over *reclaim from it*.
There is no reclaim in this kernel, and inventing one inside a fault handler
that may not take a lock would be the wrong place for it even if there were.

### Concurrency

No new lock, and no lock taken anywhere new. Two atomic arrays, relaxed
ordering for the counter — it guards no other memory, and a charge that is
observed late costs a frame, not correctness. The cap is written once before
any thread of that domain exists.

### `unsafe`

None. Both crates touched already forbid `unsafe` at the sites involved, and
this adds no new block, so the budget does not move.

## What the boot measured (2026-09-19)

On the `bios` lane, after the change:

```
envelope   1118 frame(s) charged across 12 live domain(s); fullest vfs
           at 806 of 4096; 0 with a space and nothing charged;
           page tables hold 306 more, uncharged (9372 taken, 9066 given back)
```

Three lanes, and they agree. `bios` as above; `iommu`, which runs the
filesystem, the network and the hosted programs, reads 1,171 across 15 domains
with 313 in page tables; the BusyBox lane reads 996 across 9 with 274. The
fullest domain is `vfs` at 806 of 4,096 on all three — a fifth of its
envelope — and the page-table ratio is 0.27× on all three.

**No live domain is near its envelope.** The fullest is `vfs` at 806 frames of
4,096 — about 20%. So the default envelope is not tight for anything this
machine runs, and nothing had to be raised to keep a lane green. That was the
open risk of the whole change and it is answered by a number rather than by
hoping.

**Those figures read 182 and `net-keeper` at 89 for an afternoon, and the
difference is a bug this section found.** A space is *mapped before it is
owned*: `started_program` maps a stack, loads an ELF and only then calls
`install`, which is where the domain becomes known. The owner was being set at
`install` and took over an empty ledger, so **936 frames a boot — a program's
entire initial image — were charged to nobody**, and the accounting undercounted
by six times while looking perfectly healthy. `AddressSpace` counts what it
holds regardless of owner now, and `own` hands that total over.
`envelope_self_test`'s fifth arm is that case, and it was watched red.

**The boot also counts the shape of that bug now, which the numbers alone did
not show.** `N with a space and nothing charged` is on the report and gated at
zero: a program holding an address space has a stack and an image in it, so
zero frames means the space's frames never reached its owner. Reintroducing
the bug prints `5 domain(s) hold an address space charged to nobody` and fails
the lane. A total that is simply *too small* is invisible; a domain that
should be paying and is paying nothing is not.

**The page-table gap is about a quarter of what the envelope bounds.** 306
frames of page tables against 1,118 charged — 0.27×. That is small enough to
leave, which is what the design section's test asks.

**And that conclusion was written the other way round first, off the
undercount.** Against 182 charged the same 306 read as 1.7× — *larger* than the
memory being bounded — and this document, `security.md` T10, `memory.md` and
`TRACKER.md` all said so before the ownership bug was found. A ratio is two
numbers, and only one of them was wrong.

**And the first reading of that number was wrong, by a factor of thirty.** The
counter was a tally of allocations, not a gauge of frames held, and it read
**9,368** — which looks like page tables costing fifty times the memory they
map. The frame-leak gate builds and destroys a thousand address spaces inside
every boot, and all of them were in that figure. `AddressSpace::destroy` gives
its page-table frames back to the counter now, and the boot prints the traffic
beside the gauge — `9368 taken, 9062 given back` — so the difference cannot be
read as the total again.

**A second wrong reading, caught by the same discipline.** The eager arm of the
gate first asserted that a refused mapping takes no frame from the allocator,
and it went red for one frame. It was not the mapping: `RangeMap` holds a
`Vec`, so the *first* region inserted into a fresh address space grows the
kernel heap, and the heap does not hand frames back to the physical allocator.
The gate maps a page that fits before it tries one that does not, which warms
the map and lets the check mean what it says.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Call `domain::charge_frames` from the fault path as it is | Takes `TABLE.lock()` at `Rank::Domains` from a context that may not block. This is the hang that `vm.rs:1135` and the `try_lock` on `SPACES` were both written about | The domain table itself becomes lock-free for reads, at which point this is the same design |
| Keep the counter in the `AddressSpace`, under the `SPACES` lock the fault path already holds | Gives a domain two independent caps — one for shared objects, one for its own memory — so the envelope bounds 2× what it says. A cap that means half of its number is the defect this RFC is closing, one layer up | The envelope is redesigned to name the two consumers separately and on purpose |
| Draw a reservation from the envelope at space creation and spend it lock-free | Correct and strictly more complex: a reservation that runs out mid-fault needs a top-up, which needs the lock, which is where this started. It also makes a domain's charge depend on when it was refilled rather than on what it holds | The per-fault atomic is ever measured to cost something, which it is not expected to |
| Charge page-table level frames too, in this change | The unwind on a partially built page table is its own piece of work, and doing it badly inside a fault handler is worse than not doing it. Left out **and counted**, so the gap is a number | The count printed by this change turns out to be a material share of a domain's footprint |
| Raise the default envelope so nothing is refused | That is not a mitigation, it is the gap with a larger number in it | — |

## Impact on existing design documents

**[security.md](../security.md) §1, T10.** The status cell reads 🔨 *partial*
and its note says the memory half is not built. Both become accurate to the
tree in the same change: what is built, and what is left (page-table frames,
counted and printed).

**[security.md](../security.md) §1, the note under the table** — *"a gate that
exercises the mechanism rather than the property will pass while the property
is absent"* — stays, and gains the sentence saying which gate now tests the
property.

**[memory.md](../memory.md).** The invariant above belongs beside the
allocation rules, because a design document that does not state it is how the
next allocation path gets written without a charge.

## Security implications

Closes the memory half of **T10**. Introduces no new authority: the envelope is
set at `domain::create` by whoever creates the domain, exactly as the CPU,
capability and child-domain caps already are, and nothing in this change lets a
domain read or raise its own.

No new parser and no untrusted input, so no fuzz target is owed.

**One new denial-of-service shape is created and is the intended trade.** A
domain whose envelope is too small for the program it runs now dies where it
previously ran. That is the point of a cap; what makes it safe to ship is that
the boot report prints every domain's charge against its cap, so an envelope
that is too tight is visible before it is load-bearing rather than after.

## Performance implications

One atomic compare-exchange per frame entering an address space, on paths that
already allocate, zero and map a page. It should be unmeasurable against the
`write_bytes` of 4,096 bytes two lines away.

What will be measured: the boot report's existing frame figures, before and
after, on the `iommu` lane — and the new per-domain line, which is also the
number that sizes the page-table gap.

## Testing plan

**Host** — the accounting, which is pure logic: a charge that fits, a charge
that does not, a charge that exactly fills the cap, a release that returns it,
a release of more than was charged saturating at zero, a reused slot that does
not inherit its predecessor's charge, and two charges racing one cap where at
most one may win — sixteen threads against a cap of eight, two hundred times.
The four existing `domain::tests` assertions move onto `FrameBudget` and must
pass unchanged, because the move is not meant to change what the accounting
means.

**QEMU** — a boot gate that asserts the **property**, not the mechanism:
`vm::envelope_self_test`, in six arms. A domain is created with a small
envelope; it maps up to its cap; the next page is refused;
`heap::available_frames()` is unchanged across the refusal. Both arms of the
fault path are exercised separately, the demand-paging one and the
copy-on-write one. Then the teardown must return every frame; a space mapped
*before* it was owned must hand its frames over when it acquires one; and a
fault in a space whose domain has ended must say that rather than report a
full envelope.

**One thing the arms could not check, so the boot counts it instead.** Every
arm above builds a space that is owned before it is used, which is exactly why
all of them stayed green while a program's real initial image went uncharged.
The report therefore carries `N with a space and nothing charged`, gated at
zero: a domain holding an address space has a stack and an image in it, so
zero frames means the space's frames never reached its owner.

**Armed before it is believed**, per coding-style.md §8, all six: the charge
removed from `map_anonymous`, from the demand-paging arm and from the
copy-on-write arm in turn; the release removed; the hand-over removed, which
reddens both the transfer arm and the counter above; and the two charge errors
collapsed into one message, which makes the sixth arm print the wrong
diagnosis it exists to prevent. An assertion that cannot be made to fail is
not testing what it claims and does not ship.

**Real hardware** — nothing here is hardware-dependent, and the SR550 lane
inherits the gate with everything else.

## Unresolved questions

1. **Page-table frames.** Counted by this RFC and charged by none. The count
   it prints is what should decide whether to charge them, and on the day it
   read **306 held against 1,118 charged — 0.27×**, which is small enough to
   leave. So the question stays open rather than answered, and it now has a
   trigger instead of an opinion: **if that ratio passes 0.5, charge them.**
   The unwind on a partially built page table is the work it would need, and
   is why it is not in this change.

   *This entry said the opposite for an afternoon* — "the count decided it,
   worth closing, 1.7×" — computed against a charged figure that was six times
   too low because a space's frames were not transferred to its owner. The
   denominator was the bug, not the numerator.

   A domain can still spend uncharged memory this way, bounded by how much
   address space it maps rather than by its envelope, so **T10 is mitigated
   rather than closed** — which is what `security.md` says.
2. **What a hosted Linux process should be told** when its domain's envelope
   refuses a page. Today it takes the ordinary fault crossing and `bin/linuxd`
   decides. Whether that should become a distinguishable `ENOMEM` at the
   `mmap`/`brk` that over-committed, rather than a fault at first touch, is the
   personality's question and not the nucleus's.
3. **Whether `forget()` should release.** It does not free frames — its doc
   comment says the page tables are deliberately left — so the charge returns
   with the domain slot instead. If address spaces ever are destroyed on domain
   end, this moves.

## Implementation plan

Each step is separately testable, and the order is chosen so nothing is charged
before there is a counter that can be read without a lock.

1. ✅ **The accounting becomes lock-free.** `domain::FrameBudget`, one per slot
   in `BUDGETS`, a compare-exchange charge, the cap published at creation and
   the slot cleared on reuse. The four envelope host tests move onto the
   budget, and a fifth is added: sixteen threads charging one frame each
   against a cap of eight, two hundred times, where exactly eight may win.
   Armed by replacing the compare-exchange with a read-then-write — nine
   granted against a cap of eight.
2. ✅ **An address space knows its owner.** `owner: Option<DomainId>` on
   `AddressSpace`, set in `register_for` and `install` and nowhere else.
   `None` is the kernel's own and is charged nothing.
3. ✅ **The eager path charges.** `map_anonymous` charges the range before
   allocating, releases it on the unwind, and answers
   `VmError::MemoryEnvelopeExceeded`.
4. ✅ **The fault path charges.** One frame in each of `service_fault`'s two
   creating arms, refused as `FaultOutcome::Refused("the domain's memory
   envelope is full")`; `unmap_pages` and `destroy` release what they free.
5. ✅ **The report and the gate.** The `envelope` line in the boot report, the
   property gate in `vm::envelope_self_test`, and the correction to the old
   gate's comment in `boot-test.sh` saying what it actually tests. **Six
   assertions, each armed red**: the eager charge, the demand-paging charge,
   the copy-on-write charge, the release, the transfer of a space's frames to
   an owner it acquires late, and — the sixth — that a fault in a space whose
   domain has *ended* says so rather than reporting a full envelope. Two
   errors are two diagnoses pointing at different halves of the system, and
   naming one as the other is the mistake this project's tracker records
   costing a day more than once. That case ought to be unreachable, since
   `domain::end` calls `vm::forget`; "ought to be unreachable" is a reason to
   name it, not a reason to leave it.

   **The change also took twelve lines *out* of the kernel's `unsafe` budget,
   which is the first time that number has fallen.** Counting a page-table
   frame needed a line inside three allocator closures, and those closures sat
   lexically inside the `unsafe` blocks that call `map_page` and
   `create_address_space` — so safe arithmetic was costing `unsafe` budget.
   The closures are bound outside the blocks now and only the calls remain in
   them. Nothing about the machine got safer; the number stopped counting
   something that was never unsafe. `kernel/Cargo.toml` is lowered from 2,062
   to 2,050 rather than left with slack, because a budget with room in it is
   not what makes growth visible.
6. ✅ **The documents.** `security.md` T10, `memory.md`'s accounting section,
   `TRACKER.md`.

**One existing test changed with the code, and it is worth naming.**
`vm::supervisor_write_self_test` registered its space for `NOBODY`
(`0xffff_fffe`) — "a domain id nothing owns", chosen because no operation
resolved it. A fault that charges its owner resolves it, so the commit that
test exists to prove would have been refused. It creates a real domain now,
and asserts the commit was charged to it — which is the supervisor half of
this property: a page committed on a domain's behalf by somebody else is
still the domain's memory. Letting an unresolvable owner mean *uncharged*
was the alternative, and it is this RFC's own hole reopened as a special case
for a test.
