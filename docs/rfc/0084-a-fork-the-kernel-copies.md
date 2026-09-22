# RFC 0084: a fork the kernel copies

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-22 — built and gated; the boot property holds and every assertion was armed red before it was believed.** A domain can be given a copy of another domain's address space by a single nucleus method, and `bin/linuxd`'s `fork` uses it. The acceptance call is the project lead's. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`vm`, `syscall`), userspace (`bin/linuxd`) |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0032](0032-a-supervisor-interface.md) (the supervisor methods this joins), [RFC 0033](0033-what-a-hosted-process-is.md) (the `fork` that needed it), [RFC 0082](0082-a-domains-own-memory-is-its-own.md) (which charges the receiver); answers [RFC 0083](0083-a-signal-a-process-can-catch.md)'s unresolved question 4 |

---

## Summary

A new method on a `Domain` capability, `COPY_SPACE`, gives the domain it names
a copy of the address space of another domain the caller also holds. The
regions come across with their protections and their bytes; regions whose
frames belong to somebody else — a `Memory` object, or a device window — are
**skipped and counted** rather than silently reproduced or silently dropped.
`bin/linuxd`'s `fork` becomes one invocation where it was a walk of the regions
the adapter happened to remember, copied a kilobyte at a time.

## Motivation

**A forked hosted process does not get its parent's memory.** It gets the part
of it `bin/linuxd` remembers, which is only what the adapter answered `mmap`
for. `execve` maps a program's segments and its stack with `map_at_eager` and
never records them, and a hosted program the *kernel* started has its whole
layout mapped by `run_bell_program`, which the adapter never sees at all. So a
child was forked without its code and without its stack.

That is not a subtlety. It is why every hosted probe in this tree contorts:
their forked children have to run out of a page the parent `mmap`'d by hand,
and RFC 0083 had to hand a child a stack before a signal frame could be built
on it. A `fork` whose child cannot execute the instruction after it is not a
`fork`; it is a domain with a pid.

**The reason this project gave for not fixing it was measured on 2026-09-22 and
was wrong.** RFC 0083's question 4 said recording `execve`'s regions would cost
more than it is worth, because every BusyBox `fork` would copy 2.1 MB for a
path that `execve`s immediately and throws it away. The boot instruments both
sides:

| | bytes | pages | through `COPY_OUT` | in the kernel |
|---|---|---|---|---|
| a fork today | 8,192 | 2 | 426,808 | 280 |
| the `execve` stack | 65,536 | 16 | 3,414,464 | 2,240 |
| `bin/hosted` | 85,512 | 21 | 4,481,484 | 2,940 |
| BusyBox | 2,172,376 | 531 | 113,317,524 | 74,340 |

A page costs **213,404 cycles warm through `COPY_OUT`** — two crossings, because
the staging object is smaller than a page — against **140** through the
kernel's direct map. A factor of **1,524**. Copying the whole of BusyBox in the
kernel costs under a sixth of what copying today's 8 KiB through the adapter
costs.

**The expensive thing is the crossing, not the megabytes.** The conclusion that
the adapter should not record `execve`'s regions survives; its reason does not.
A supervisor copying an address space a kilobyte at a time is the wrong
mechanism at any size, and the cross-domain copy-on-write that entry reached
for is not needed to make the cost acceptable — it is needed only if the
copying stays in ring 3. So the work belongs where these pages already move for
every `execve`.

## Design

### One method, and the authority rule is the one already there

```text
  COPY_SPACE  on a Domain capability -- the TARGET
              arg0 = the caller's slot holding the SOURCE Domain
```

The caller must hold both capabilities. That is the whole of the authority
rule, and it is the same one `MAKE_SPACE` and RFC 0080's `END` live under: a
supervisor may do to a domain what holding its handle permits, and it cannot
name a domain it does not hold. A caller that could pass a domain *number*
would be reading another program's memory with an integer; it passes a slot in
its own CSpace and the capability arena says what is there.

**Phrased generically, as RFC 0032 requires.** *"Give this domain a copy of that
one's address space."* Nothing in the method names a Linux concept, exactly as
`MAKE_SPACE` insists on *"this domain needs an address space"* rather than on
the `execve` that first wanted one. `fork` is the first caller, not the
definition.

### What is copied, and what is refused

`AddressSpace` already records what backs every region, and the decision is
that enum:

| `Backing` | what happens |
|---|---|
| `Anonymous` | the region is reproduced, and every page the source has a frame for is copied through the direct map |
| `Reserved` | the range is reproduced with nothing behind it — a guard page that is not there is not a guard |
| `Shared` | **skipped and counted.** Those frames belong to a `Memory` object, and the target holds no capability naming it. Reproducing the mapping would hand it memory nobody granted, which is manufacturing authority rather than copying a space |
| `Direct` | **skipped and counted**, one step along: device registers are not the target's to have either |

**The skips are reported.** A copy answers three numbers — regions reproduced,
frames moved, regions skipped — packed into the one word an invocation returns.
Three rather than a bare success, because *"the child has a copy"* and *"the
child has a copy of everything that could be copied"* are different claims, and
a `fork` whose child quietly lacks a mapping is the failure this whole change
exists to remove.

### Lazily, and then page by page

A region records a range the source *may* touch; the page table records what it
has. The copy reproduces the **region** for every anonymous mapping and
materialises only the pages the source actually holds a frame for. Mapping
every region eagerly would charge a child for every page its parent reserved
and never used, which for a program that reserves a heap and uses a corner of
it is most of them. A page the target was not given reads as the same zero it
would have read in the source, and faults in on first touch like any other.

### RFC 0082 does the accounting, and it does it for free

The target's space is owned **before** anything is mapped into it, so every
frame is charged to the target's envelope as it arrives. A copy the target
cannot afford is refused with `QuotaExceeded`. A `fork` can therefore now fail
for want of envelope, which is correct and was not previously possible.

### Failure behaviour

Every refusal below is **reasoned and ungated**; see *Testing plan*.

- **The target already has a space, or has threads** — refused with
  `SlotUnavailable`, for `MAKE_SPACE`'s reason: somebody is running in memory
  this would replace.
- **The source has no space, or is not a `Domain`** — `NoSuchCapability`.
- **The caller lacks `READ` on the source** — `InsufficientRights`. The check
  at the top of `domain_supervise` demands `WRITE` on the capability the method
  is invoked on, which is the domain being *written into*. This call also reads
  every byte of somebody else's address space, and the capability that says who
  may do that is the source's.
- **The envelope is full** — `QuotaExceeded`, with nothing mapped and nothing
  charged.
- **Out of frames** — `Exhausted`, likewise.

**A failure half way through tears the space down.** `map_anonymous` unwinds its
own call, which is not the same thing: a copy refused on its third region has
two mapped, and `AddressSpace` has no `Drop` — dropping one leaks every frame
in it and leaves the target charged for memory it does not have. So the region
walk is a separate function whose caller destroys the half-built space on any
error.

### Concurrency

The source's regions are taken out of the space table under its lock and the
walk runs outside it, because the target's space is built with the heap lock
and the table may not be held across it (`kernel/src/sync.rs` ranks
AddressSpace below Heap). The target has no threads — that is checked before
anything is built — so nothing is running in the space being written, and no
CPU holds its root in `CR3`.

### `unsafe`

One block: `core::ptr::copy_nonoverlapping` between two frames reached through
the direct map. The frames are distinct by construction — the target's came
from the physical allocator a moment earlier with nothing else referring to it,
and the source's belongs to a space the call only reads. The helper that maps a
single page into a region already in the map hands back a frame it has **not**
zeroed, and that is a contract rather than an optimisation: its only caller
overwrites all 4,096 bytes of it immediately. A second caller must do the same
or zero it, because a frame reaching another domain with somebody's bytes in it
is a disclosure, and `docs/memory.md` §2 puts zeroing on allocation for exactly
that reason.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Record `execve`'s regions and keep copying in `bin/linuxd` | Fixes half of it — a kernel-started program's layout is still invisible to the adapter — and keeps the mechanism that costs 1,524× per page. The measurement above is what settled it | Never; the measurement is the argument |
| Cross-domain copy-on-write | The reach for it was a consequence of the wrong cost model: it is needed only if the copying stays in ring 3. It is a real future optimisation, not a prerequisite | A fork's frames are measured to be mostly untouched before `execve` — which needs the fork to exist first |
| Share the parent's frames read-only and fault on write | That is cross-domain copy-on-write wearing a smaller hat, and it needs a revocation story for frames two domains map. RFC 0009's `Memory` object exists precisely so that shared frames have an owner; inventing a second unowned sharing path undercuts it | The above, plus an owner for the shared frames |
| Reproduce `Shared` regions by granting the target a capability to the object | Manufactures authority. A `fork` would hand a child a capability its parent was given by someone else, with no record of the grant | A capability-copy is designed on purpose, as its own method, with its own rule for what may be copied |
| A method that copies one region at a time, the supervisor driving the loop | Every failure becomes half a space with the supervisor holding the pieces, and the all-or-nothing refusal above becomes impossible to state | Never |

## Impact on existing design documents

- **[RFC 0083](0083-a-signal-a-process-can-catch.md) unresolved question 4** is
  answered by this RFC rather than left open. The entry's conclusion stands and
  its stated reason is corrected in place, with the measurement, by the commit
  that took it.
- **[RFC 0033](0033-what-a-hosted-process-is.md)**'s `fork` no longer copies the
  regions the adapter remembers. The child gets its parent's space.
- **[docs/memory.md](../memory.md) §2** is *cited* rather than changed: the
  unzeroed frame above is an exception the helper documents and bounds to one
  caller.
- **`TRACKER.md`** gains the decision row and the changelog entry in the same
  commit, and `docs/progress.md` is regenerated from it.

## Security implications

See [docs/security.md](../security.md) §1.

- **New authority?** No. The method requires the caller to hold both domains,
  which is what it needed to build either of them.
- **Reachable without a capability?** No.
- **New parser for untrusted input?** No. The inputs are a capability slot and
  a domain handle.
- **The interesting question is the reverse one**: could a copy give a domain
  memory nobody granted it? That is exactly what the `Shared` and `Direct`
  skips refuse, and it is gated on every boot rather than argued here. A domain
  whose parent holds a `Memory` object does **not** inherit the mapping, and
  the count says so rather than the child discovering it by faulting.
- **T11 is unchanged.** A compromised `bin/linuxd` could already build a domain
  and map memory into it; it can now do so more cheaply. The blast radius is
  the one RFC 0033 priced.

## Performance implications

The claim is the measurement above: **1,524× per page** against the path this
replaces, on the boot's own instrumentation. A fork that moves 2 pages costs
280 cycles in the kernel where it cost 426,808 through `COPY_OUT`. The boot
prints what a fork moved, so the claim is re-measured on every run rather than
asserted once.

What gets slower: nothing measured. What could: a `fork` of a process with a
large *touched* heap now really copies it, where before it copied nothing and
the child could not run. That is a cost this system did not previously pay
because it was not doing the work.

## Testing plan

- **Host.** The region decision is a `match` on `Backing` and is covered by the
  `mm` crate's own tests for what each kind means.
- **QEMU — the property, on every boot.** A source space is built with a
  written page, a guard, a region whose frames belong to a `Memory` object, and
  a range reserved and never touched. The copy must give the target the written
  page **with the source's bytes in it**, in a **different frame** — a share is
  not a copy — must reproduce the guard with nothing behind it, must not
  reproduce the shared region, must reproduce the reserved range without
  materialising it, and must refuse a target whose envelope is empty with
  nothing mapped, nothing charged and no space left behind.
- **Armed.** Every assertion was watched red before it was believed: the shared
  region reproduced (*"a region belonging to a memory object was reproduced"*),
  the bytes not copied (*"the child received the page without its parent's
  bytes"*), and the reserved range materialised (*"a page the source had
  reserved and never touched was materialised"*).
- **The caller is the second gate.** `bin/linuxd` uses the method, deliberately
  rather than optionally: a mechanism with no caller is untested in the way
  that matters, and this tree records that *a crate that is not named is a
  crate that is not tested and nothing says so*. The hosted `fork`, `kill` and
  signal probes are what say whether the children really do inherit.
- **Real hardware.** Nothing here is device-dependent; the SR550 runs the same
  gate on the same boot.

**What is *not* gated, said plainly.** The five refusals that live in the
syscall arm — target already has a space, target has threads, source is not a
`Domain`, source has no space, and the caller lacks `READ` on the source — are
reasoned and unexercised. Every caller that exists holds a full-rights handle
to a freshly spawned domain with no space and no threads, so no gate here can
reach them; the boot self-test calls `vm::copy_space` directly and is below
that layer. They are recorded as a gap rather than described as tested, which
is the same distinction this tree draws between what is proven and what merely
compiles. Closing it needs a probe that holds a deliberately diminished
capability, which is worth building for the whole supervisor interface and not
for this method alone.

## Unresolved questions

1. **Copy-on-write across domains.** Now a real optimisation with a real
   measurement behind it rather than a prerequisite. Needs an owner for frames
   two domains map, which is what RFC 0009's `Memory` object is for and why
   this is not a small change.
2. **`vfork`.** Linux's answer to "fork then exec immediately" is to not copy
   at all. Cheaper than any copy, and it needs the parent suspended until the
   child execs — which this adapter can express and has not been asked for.
3. **The frames a domain's space leaks when it ends.** `domain::end` calls
   `vm::forget` and not `AddressSpace::destroy`, because destroying a space
   needs every CPU moved off its root first. A `fork` that copies more makes
   that leak bigger. Named here because this change moves the number, not
   because it introduces it.

## Implementation plan

1. `abi/src/lib.rs`: `COPY_SPACE = 75` and its contract, including the packed
   return.
2. `kernel/src/vm.rs`: `copy_space`, the region walk, and the single-page
   populate helper.
3. `kernel/src/syscall.rs`: the method arm beside `MAKE_SPACE`'s, with the two
   refusals it shares.
4. `kernel/src/lib.rs` and `tests/qemu/boot-test.sh`: the boot self-test and
   the gate, armed each way.
5. `user/linuxd/src/main.rs`: `build_fork_child` calls it.
6. `TRACKER.md` and `docs/progress.md`, in the same commit.
