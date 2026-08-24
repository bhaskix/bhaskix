# RFC 0044: Revocation that reaches the mapping

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-08-23, all seven steps implemented and gated, awaiting the project lead's acceptance.** Opened the same day [RFC 0005](0005-linux-abi-compatibility.md) step 8 found the hole and published it unfixed, and the same day the *first* description of the fix turned out to be wrong — see "The obvious fix is worse than the bug" |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/syscall` (`method::REVOKE`), `kernel/shared`, `kernel/cap` |
| **Milestone** | Phase 2. It adds no feature; it makes a rule this project has claimed since M5 actually true |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (the four capability rules, of which this is rule 3), [RFC 0009](0009-shared-memory.md) (the `Memory` object and its mapping list), [RFC 0016](0016-capability-in-a-reply.md) (the lending this breaks today), [RFC 0012](0012-iommu.md) (the device half of a revocation) |

---

## Summary

`method::REVOKE` destroys capabilities and does not unmap the memory they
named. A domain that borrowed a page keeps reading the frame after the lender
has revoked the loan, unpinned the frame and refilled it with somebody else's
data. This RFC makes revocation take the mapping with it — from the address
spaces of the holders being revoked, and without destroying the object the
owner still holds — and moves the unmapping outside the two locks that make it
impossible today.

## Motivation

`security.md` §2 states four rules the capability system is built on. Rule 3 is
**immediate transitive revocation**: *"`revoke(cap)` invalidates every
capability derived from it, transitively, before returning. Deferred revocation
is a vulnerability with a delay fuse."*

It is true of capabilities and false of memory. `method::REVOKE` calls
`cap::Arena::revoke_tallied`, which destroys arena nodes and touches no page
table. The kernel's own words for why that is wrong are already in this tree,
on `shared::revoke`:

> **a revoked capability whose pages are still mapped is not revoked, it is
> renamed.**

**This is not a hypothetical.** `bin/fsd` lends one page of its block cache to
a reader — `dir::MAP` — and takes it back by revoking, `dir::RELEASE`, whose
documentation promises:

> So a caller that says it is done **is** done: the page is gone from its
> address space when this returns, and reading where it used to be is a fault.

The page is not gone. The borrower keeps a read-only mapping; `bin/fsd`
unpins the frame; the cache reuses it for another file's block; and the
borrower reads that block. That is precisely the disclosure `dir::MAP` was
designed to avoid — *"a capability to the cache would be a capability to every
block in it"* — arriving a moment later instead of immediately.

**It was found as a functional bug, which is the only reason it was found at
all.** With the address still occupied, the borrower's next `ATTACH` at the
same address is refused `SlotUnavailable`, so `bin/linuxd` — which borrows into
one fixed slot — can serve a hosted `read` **once per machine rather than once
per file**. RFC 0005 step 8's probe therefore does not read, and says so.
Nobody had ever read two files.

**And the rule is gated.** The boot gate *"two domains share an object,
revocation takes it from both, nothing leaks"* passes on every placement. It
passes because it calls `shared::revoke_capability` **directly**, from a kernel
self-test — the only caller in the tree. The syscall path does not use it. So
the rule is enforced where it is measured and unenforced where it is used,
which is the worst of the two arrangements: the gate is green and the property
is absent.

### The obvious fix is worse than the bug

When this hole was first written down — in `security.md`, in RFC 0005's step 8
record, and in `TRACKER.md`, all pushed — it said the function that does it
correctly already exists and is merely not called. **That was wrong, and the
correction is the most useful paragraph in this document**, because a reader
who took it at face value would have written a worse bug than the one being
fixed.

`shared::revoke_capability(slot)` does two things:

```rust
let mappings = object.and_then(from_identity).map_or(0, revoke);
let capabilities = crate::cap::with_arena(|arena| arena.revoke_unchecked(slot));
```

- `shared::revoke(id)` unmaps from every address space **and ends in
  `destroy(id)`**, which frees the object's frames to the buddy allocator and
  releases the owner's quota.
- `revoke_unchecked` skips the `REVOKE`-rights check *and* the per-owner tally
  that `method::REVOKE` owes for quota.

Both are right for that function's one caller, which revokes an object's
**root** capability — the owner's own — as part of destroying it. Both are
catastrophic for the syscall. `bin/fsd` derives its lending capability from the
capability naming its **own pinned cache frame** and revokes *the lending*:

```
CACHE_SLOT + frame   the frame itself, held by bin/fsd, still in use
  └── LEND_SLOT + frame   derived, READ|GRANT|DERIVE|REVOKE
        └── the borrower's copy, installed by HAND
```

Routing `method::REVOKE` through `revoke_capability` would hand
`CACHE_SLOT + frame`'s frame back to the allocator while `bin/fsd` was still
reading out of it, and would do it without checking that the caller was allowed
to revoke anything.

What is reusable is the **order** — mappings out before the derivation tree,
which `shared::revoke`'s own comment calls the design — and the
unmap-and-shoot-down loop inside it. What does not exist is the operation
actually needed:

> Unmap this object from the address spaces of the holders being revoked, and
> **leave the object alive**.

## Design

### 1. The set of holders is already computed

`revoke_tallied` fills a `[u32; MAX_OWNERS]` tally — how many nodes each domain
lost — because the quota has to be given back. That array *is* the set of
holders being revoked, and no new bookkeeping in the arena is needed to obtain
it. A domain with a non-zero tally lost at least one capability naming the
object; its mapping goes.

### 2. Whose mapping — and why "everyone in the tally" is wrong

A `Mapping` records `{ root, address, pages }` — the address space, not the
domain and not the capability that authorised it. So "unmap what this holder
mapped" is answered by matching `root` against `domain::space_root_of(d)`.

**But the tally is not the answer, and the motivating caller is what proves
it.** This section first said a domain holding two capabilities to one object
should simply lose its mapping when either is revoked — blunt, safe, and the
holder may `ATTACH` again. Then the first line of the implementation checked
what `bin/fsd` actually does:

```
CACHE_SLOT + frame   the frame, held by bin/fsd, ATTACHed at CACHE_AT + n*4096
  └── LEND_SLOT + frame   derived, and what dir::RELEASE revokes
        └── the borrower's copy
```

`destroy_subtree` kills the lending **and** the borrower's copy. The lending is
`bin/fsd`'s own node, so `bin/fsd` is in the tally of every release it
performs — and the blunt rule would unmap its own cache page out from under it,
every time, on a path taken by every file read on the machine. Not an edge
case: the first caller, always.

So the rule is one refinement narrower, and the refinement is not optional:

> A holder loses its mapping when it loses **every** capability naming the
> object. A holder that still names it keeps what it mapped.

`bin/fsd` still holds `CACHE_SLOT + frame`, so its mapping stays. The borrower
holds nothing naming the object, so its mapping goes. The question is answered
inside the arena, where the nodes are — `CapNode` records `object` and `owner`
— which is also where the tally is computed, so it costs one pass and no new
bookkeeping.

**What this knowingly does not do** is compare *rights*. A holder whose
surviving capability is `READ` while the revoked one carried `WRITE` keeps a
writable mapping. That is a narrower hole than the one being closed and it is
recorded rather than fixed: closing it needs the mapping to record its
protection and its authorising capability, which is bookkeeping on `ATTACH`,
a hot path, for a case no program in this tree has. Named in unresolved
questions with its trigger.

### 3. The lock inversion, which is the whole reason this is an RFC

`invoke_capability` runs inside `domain::with` (`Rank::Domains` = 6) and
`cap::with_arena` (`Rank::Capabilities` = 7). Unmapping needs:

| | |
|---|---|
| `Rank::TlbSender` = 4 | a shootdown interrupts every other CPU |
| `Rank::Heap` = 3 | page-table walks |
| `Rank::AddressSpace` = 0 | |

All three are **outer** to the locks already held, so the work cannot happen
where the decision is made. This is the same constraint `shared::revoke`
already states — *"do the page-table work outside it"* — and the same one that
made `GRANT` a function lifted out of the dispatch, and `ResolvedWindow` a
struct returned from it.

So: `invoke_capability` **plans** and `invoke` **performs**.

```rust
/// What a revocation still owes once the arena and domain locks are gone.
struct Unmapping {
    object: MemoryId,
    roots: [Option<u64>; cap::MAX_OWNERS],
}
```

`invoke_capability`'s `REVOKE` arm additionally reports the object's identity
when it is a `Memory` object. `invoke`, which already holds the tally, resolves
each tallied owner to its space root **before** entering `shared` — because
`space_root_of` takes `Rank::Domains` (6) and `shared::ARENA` is
`Rank::SharedMemory` (12), so taking the domain table under the shared arena
would be an inversion of its own. Roots, not domain ids, cross the boundary,
and `shared` stays free of the domain table.

### 4. The new operation

```rust
/// Unmaps `id` from each address space in `roots`, leaving the object alive.
///
/// Returns how many mappings were removed.
pub fn unmap_roots(id: MemoryId, roots: &[Option<u64>]) -> usize
```

Same shape as `shared::revoke`'s body and the same order: take the matching
entries out of `object.mappings` under `ARENA`, drop the lock, then
`unmap_page` and `tlb::shootdown` per page. **It does not call `destroy`** and
does not free a frame — the object outlives the loan, which is the entire
difference from `revoke`.

Removing the entries from the mapping list is not bookkeeping: a stale entry is
a `root` and address that a later, unrelated revocation would unmap, and by
then that address may belong to something else in that space.

**And a second half this section did not have when it was written.** Clearing
the page-table entries is not enough: an `AddressSpace` keeps a *region map*
beside its tables, and `shared::revoke` has always edited the tables by root
and left the region alone. So the address stays occupied — the holder can
never map anything there again, and the symptom is an `ATTACH` refused
`SlotUnavailable` at an address nothing appears to be using. That is exactly
how RFC 0005 step 8 met this bug, and a fix that stopped at the page tables
would have left the half that was actually visible.

`AddressSpace::unmap` is the other half: it removes the region and, for a
shared backing, **deliberately does not touch the pages**, because teardown
must not free frames the object owns. So both calls are needed and neither
substitutes for the other. `vm::with_space(root, …)` reaches the holder's
space — which is also why the address spaces in the self-test have to be
*registered*: a space nobody installed is a space no revocation can find, and
the first version of that test passed the page half and silently lost this one.

The order is fixed by the ranks, not by preference: `Rank::AddressSpace` is 0
and the shootdown's `Rank::TlbSender` is 4, so the region goes first. The
window that opens is "the region map says free, the hardware still maps it",
and a thread racing into it gets a region it may fault on, which is safe.

### 5. The device half, which was question 1 and is now a field

A domain does not only map an object into its own address space. Holding a
`DmaWindow` capability, it can `method::MAP` a `Memory` object into a
**device's** translation, and `shared::revoke` already takes that mapping out
for exactly the reason this RFC exists: *"a revocation that removed a page from
every address space and left a device reaching it would be the same failure as
leaving one CPU's TLB entry behind — gone from the tables, and still working."*

So the question was whether a revoked holder can leave a device mapping behind,
and the answer, from reading the one caller of `record_device_mapping`, is
**yes in principle and no today** — which is precisely the shape the main bug
had before somebody read two files. Nothing in the tree holds both a lent
`Memory` capability and a `DmaWindow`: window capabilities go to drivers, and
no driver borrows a lent page. "Not yet live" is how this hole got here.

`Object.device` is a single `DeviceMapping { address, pages, device }` — at
most one per object, and it **does not record which domain made it**. So the
record cannot answer "was this the revoked holder's?" and the design has two
ways out:

- Remove the device mapping whenever the object is revoked from anybody. Safe
  against the device, and takes the *owner's* own DMA mapping away as
  collateral.
- **Record the mapping domain**, one `u32` on a struct that already carries
  three fields, and take it out when its maker is among the revoked.

The second, because it is exact, because the field is free — `map_memory` is
reached from a syscall that knows `current_domain()` — and because the first
answer would make a correct revocation of a lending break an unrelated
driver's DMA. `unmap_roots` takes the device mapping when its recorded domain
is one of the revoked, and leaves it otherwise.

### 6. Failure behaviour

- **A domain that has since died** has no space root; `space_root_of` answers
  `None` and the entry is skipped. Its mappings went with its address space.
- **An object already destroyed** resolves to nothing and the pass is a no-op.
- **A mapping list with no matching root** is the ordinary case for a domain
  that held a capability and never mapped it. Zero removed is not an error.
- **Out of memory** cannot arise: unmapping allocates nothing.

### 7. `unsafe`

One block, already written and moved rather than invented:
`paging::unmap_page(root, address, hhdm)` on a root this object recorded a
mapping into. The frame is deliberately **not** freed — the object still owns
it, and `destroy` returns it once, however many spaces had it mapped.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Route `method::REVOKE` through `shared::revoke_capability` | Destroys the object and frees its frames, and skips the rights check and quota tally. Would give `bin/fsd` its own pinned cache frame back to the allocator mid-read. **This was the published description of the fix for part of a day**, which is why it is first | Never. It is a different operation that happens to share a loop |
| Add `method::DETACH` and have the borrower unmap before replying | Fixes the *functional* half — a program could read twice — and none of the security half: the fix would depend on the borrower cooperating, and the borrower is the party that benefits from not doing so. A lender cannot make a loan safe by asking | It is worth having anyway as `ATTACH`'s missing inverse, but as a convenience and never as this fix. Out of scope here |
| Have `bin/linuxd` attach each lend at a rotating address | Every gate goes green with the disclosure untouched. This is the shape of workaround this project exists to refuse — it converts a security bug into a passing test | Never |
| Check the capability at fault time instead of unmapping | There is no fault: the mapping is present and the CPU never consults a capability. It would mean unmapping to force a fault, which is this proposal | If mappings ever became lazy for shared objects, the check could ride the fault |
| Unmap from every domain in the revocation tally | **Chosen first, and wrong.** `bin/fsd` derives its lending from the capability naming its own cache frame, so it is in the tally of every `dir::RELEASE` and would lose the cache page it is serving from. Found by reading the caller before writing the code, which is the only reason it is a table row rather than a boot | Never |
| Also compare rights, so a surviving `READ` capability does not justify a `WRITE` mapping | Needs the protection and the authorising capability recorded per mapping, on the `ATTACH` path — bookkeeping on a hot path for a case no program in the tree has | A program holds two capabilities of different rights to one object and maps it at the wider one |
| Unmap eagerly inside `invoke_capability` and accept the rank inversion | The lock-order check is a gate, not advice: it would fire on every revocation of mapped memory. And a shootdown under the capability arena serialises every CPU behind it | Never |

## Impact on existing design documents

- **`docs/security.md` §2 rule 3** carries a note added 2026-08-23 saying the
  rule has a hole. Accepting this RFC and implementing it means **deleting that
  note and saying when it closed**, not editing it into vagueness.
- **`docs/security.md` §1 T2** was moved from ✅ to 🔨 by the same finding and
  goes back, with the date.
- **`abi/src/lib.rs`, `dir::RELEASE`** — *"the page is gone from its address
  space when this returns, and reading where it used to be is a fault"* — is
  false today and becomes true. No wording change; that is the point.
- **[RFC 0005](0005-linux-abi-compatibility.md) step 8's record** says its
  probe does not `read` because of this, and its "what this does not do" list
  says a hosted program can read once per machine. Both are edited when the
  probe gains a second read.
- **[RFC 0016](0016-capability-in-a-reply.md)**'s lending is the motivating
  caller and its "what ends a lending" answer becomes complete.

## Security implications

Reference [`docs/security.md`](../security.md) §1.

- **New authority?** None. This *removes* reach: memory a domain can touch
  after this change is a subset of what it could touch before.
- **Reachable without a capability?** Today, yes — that is the bug. A revoked
  borrower reaches frames it holds no capability for. After, no.
- **A parser for untrusted input?** None. No new bytes are decoded.
- **Moves anything in or out of scope?** No. It makes an in-scope claim true.
- **T2** returns to ✅. **T11** — the hostile hosted Linux application — is
  materially reduced: the adapter is the only borrower today, and a hostile
  hosted program cannot reach the adapter's lent pages, but a compromised
  *adapter* could keep them. It cannot after this.

## Performance implications

A revocation of **mapped** memory gains a page-table walk and a TLB shootdown
per page — an IPI to every other CPU. That is not new cost invented here; it is
the cost `shared::revoke` already pays and the cost the rule requires. A
revocation of unmapped memory, which is every revocation that is not a lending,
gains one pass over an eight-entry array and no IPI.

The one cost genuinely invented here is `Arena::still_names`, which is a linear
scan of the 4,096-entry node table **per tallied owner** — and only per tallied
owner, because `&&` short-circuits on domains that lost nothing. A
`dir::RELEASE` tallies two, so it is about 8,192 comparisons of two words,
under the capability arena, per file read.

> **Correction, before this was implemented.** This section first said the
> measurement that decides whether that is acceptable is "the cost of a
> `dir::MAP`/`dir::RELEASE` pair, which the boot report prints". **The boot
> report prints no such number.** It prices `bulk cost` (RFC 0009's shared
> transfer against messages) and `linux copyout` (a page through `COPY_OUT`),
> and neither is this path. The claim was written from an impression of the
> tree rather than from the tree, which is the failure this project's own
> rules name first.
>
> So the honest position at the time: **this change shipped un-measured on the
> path it makes slower.**

### The measurement, supplied afterwards — and the first attempt at it was the wrong one

Two lines now, because the obvious measurement turned out not to answer the
question.

**What was tried first: the caller-visible `dir::RELEASE`.** `bin/linuxd` times
the whole call, which is what a borrower actually pays. Two boots:

| | first sample | second sample |
|---|---|---|
| boot A | 7,877,036 | 10,049,460 |
| boot B | 6,480,746 | 4,351,920 |

**The second sample is larger in one boot and smaller in the other**, and the
spread between boots is bigger than anything a page-table walk could
contribute. So it cannot price the revocation, and calling the pair "cold and
warm" — which the first version of the boot line did — asserts a warming the
numbers deny. What dominates is `bin/fsd`'s own work inside the call: mounting
the volume and searching its cache for the frame. The line is kept, because the
caller's cost is worth knowing, and it now says what dominates it instead of
implying a trend.

**What answers the question: the unmapping alone, where a repeat is possible.**
Measured in the kernel's own lending self-test, re-mapping each time round —
unmapping is not idempotent, and a second call would time an empty loop — and
taking the **minimum of eight**, the way `bulk cost` measures a transfer:

> **46,084 and 49,440 cycles** on two boots. About 5% apart, which is what a
> number worth quoting looks like next to the one above.

For scale, from the same boot report: a page through `COPY_OUT` costs 168,330
cycles warm, and the kernel moves a page through the direct map in 122. So the
work this RFC adds to a revocation is roughly a quarter of a page-copy across
the supervised boundary, and it is dominated by the TLB shootdown — an IPI to
every other CPU, which under TCG is expensive and on hardware would not be
free either. That is the cost the rule requires; a revocation that skipped it
would be `security.md` §2 rule 3's delay fuse.

### On real silicon, 2026-08-24: about a fifth of what the emulator said

The paragraph above ended *"neither figure is a measurement of hardware"*. It
is one now. The same self-test, on the Lenovo SR550 — one Xeon Silver 4110,
booted from its BMC's virtual media:

> **9,764 cycles**, best of eight, against **46,084 and 49,440** under TCG.

**The emulator overstated this path by roughly five times**, and the reason is
the part of it TCG is worst at: the work is dominated by a TLB shootdown, which
is an IPI to every other CPU, and cross-CPU synchronisation is exactly what an
emulator that serialises guest CPUs makes look expensive. A change judged
"about a quarter of a supervised page copy" from the QEMU numbers is nearer a
twentieth on silicon.

Nothing else about the run needed correcting: the lending self-test passed on
hardware unchanged, and no line of the boot report was red. What the machine
could *not* exercise is the rest — it has no virtio disk and no NIC this system
can drive, so `linux file`, `linux dir` and `linux socket` all took their skip
arms. That is worth as much as the number: those arms were written against
QEMU lanes that lacked the devices, and this is the first time they have been
taken on a machine that lacks them for real.

## Testing plan

**Host.** The arithmetic that can be lifted is the *selection*: given a mapping
list and a set of roots, which entries are removed. That is a pure function
over arrays and belongs in a host test, watched red by making it match on
address instead of root, and by making it remove every entry rather than the
matching ones.

**QEMU.** The property itself needs real page tables, so it is a kernel
self-test beside the one that exists — and the new one differs from it in
exactly the way the bug did:

1. An owner creates an object and maps it.
2. It derives a lending capability and hands a copy to a borrower, which maps it.
3. The owner revokes **the lending**, not the root.
4. The borrower's `translate` is `None` — *and* the owner's is unchanged, the
   object is still live, and its frames are not back in the allocator.

Step 4's second half is the whole test. A fix that unmapped both, or destroyed
the object, would pass a test that only checked the borrower — and that is the
fix this RFC exists to talk somebody out of, so the test has to be able to
catch it.

**Boot gate**, watched red three ways: by not unmapping (the borrower still
reads), by unmapping every root rather than the revoked ones (the owner loses
its page), and by destroying the object (the frame count drops).

**The end-to-end gate is the one that matters**, because it is the failure
that found this: `bin/linuxd`'s file probe reads **two different files**, or
one file twice. It cannot today. The `linux file` and `linux dir` gates both
being able to read, in the same boot, in either order, is the property.

**Real hardware.** Nothing specific. The shootdown path is exercised harder on
the SR550's sixteen CPUs than on QEMU's four, so the soak should run there once
([`bhaskix-sr550-hardware`](../../TRACKER.md)).

**Fuzz.** No new untrusted input, so no new target.

## Unresolved questions

1. **Should `method::DELETE` of a mapped capability unmap too?** Dropping your
   own last name for an object while keeping the page is not a hole — it is
   your own memory access, and revocation still finds the mapping through the
   object's list. But it is surprising. Left alone here; the trigger is a
   domain that runs out of address space this way.
2. **Should `ATTACH` record which capability authorised it, and at what
   protection?** It is what would let design §2 compare *rights* rather than
   only existence, closing the case where a holder keeps a writable mapping
   after the only capability carrying `WRITE` is revoked. Not now: bookkeeping
   on a hot path for a case no program in this tree has. **The trigger is the
   first program that holds two capabilities of different rights to one
   object**, and until then this is a narrower hole than the one being closed,
   stated rather than hidden.

## Implementation plan

1. **The selection, host-tested first.** The pure function that picks mapping
   entries by root, and its tests, before anything is wired.
2. **`DeviceMapping` gains its mapping domain**, and `map_memory` is handed
   it from the syscall that already knows `current_domain()`. One field, and
   it is what makes design §5 exact rather than collateral.
3. **`shared::unmap_roots`** — the loop, the order, and the deliberate absence
   of `destroy`. Beside `shared::revoke`, sharing its comment about why the
   page-table work is outside the arena.
4. **The plan/perform split** in `invoke_capability` and `invoke`: the object's
   identity reported out, the tallied owners resolved to roots after the locks
   are dropped, `unmap_roots` called there.
5. **The kernel self-test and its boot gate**, watched red three ways.
6. **The end-to-end gate**: `bin/linuxd` reads twice, and RFC 0005 step 8's
   probe gains the `read` it had to leave out. Measure the `MAP`/`RELEASE` pair
   before and after and record both.
7. **The documents**, in the same change: `security.md`'s rule 3 note deleted
   with its closing date, T2 back to ✅, RFC 0005's step 8 record and
   `TRACKER.md` updated to say the limitation is gone.

---

## Record (2026-08-23): what building it found that writing it did not

**Three things, and the RFC was wrong about one of them before the first line
of code.**

**The tally is not the set of holders.** Design §2 first said a domain holding
two capabilities to one object should simply lose its mapping when either is
revoked — blunt, safe, re-`ATTACH` if you still have authority. Reading
`bin/fsd` before writing the code killed it: the lending is derived from the
capability naming its own cache frame, so `bin/fsd` is in the tally of every
release it performs, and the blunt rule would have unmapped the cache page it
was serving from on the path every file read goes down. Not an edge case —
the first caller, always. `Arena::still_names` is the refinement, and the
`cap` host test is that exact shape: lender, lending, borrower, revoke the
middle one, and assert that both are in the tally and only one has stopped
naming the object.

**The page tables are half the fix.** Design §4 originally stopped at
`unmap_page` and a shootdown. The self-test failed on an assertion nobody had
written yet — the borrower could not map at its own address again — because
the `AddressSpace` region record survives an unmap by root. That is the half
the *symptom* lived in: RFC 0005 step 8 met this bug as a refused `ATTACH`,
not as a stale read. A fix that closed the disclosure and left the address
occupied would have looked complete and left a hosted program reading one file
per machine.

**And the self-test's own setup hid it once.** The existing sharing self-test
uses address spaces it never registers, so `vm::with_space` cannot find them;
copying that arrangement passed the page assertions and silently skipped the
region one. The new test registers both spaces, which is what a real domain
has. A test that cannot reach the mechanism is a test of the mechanism it
reached instead.

**Watched red, five ways**, four on the self-test and one end to end:

| Broken on purpose | What said so |
|---|---|
| The pages are not unmapped at all | *the borrower's page is gone* |
| Every holder unmapped, not just the revoked one | *exactly one mapping was taken back* |
| The object destroyed, as `revoke_capability` would | *and the object it lends from is still alive* |
| The region record left behind | *the borrower's address is free to map again* |
| `method::REVOKE` does not call `unmap_roots` — the bug exactly as it was | *only 1 hosted read reached the console; two hosted programs read a file and both must* |

The last one is the one worth having: it is the original bug, restored, and
the gate names it in the terms a reader can act on.

**A false regression, and both halves of why it was false are worth
keeping.** `shell-test.sh iommu` failed with a page fault at `0x2001_4000` —
`bin/fsd`'s own cache page, which is *precisely* the failure this RFC's design
§2 exists to prevent, so it read as a direct hit. It was not. Two mistakes
stacked:

- **Two `make`s in one tree.** The suite was running when a `make gates` was
  started beside it, and they race on `build/`. The `iommu` lane is the one
  that boots whatever image is lying around — the other three build their own
  with a `CMDLINE` and then restore the default — so it booted the wreckage.
- **And then it "reproduced" three times.** `tests/qemu/shell-test.sh` does
  not build for a lane with no cmdline; it boots `build/bhaskix.iso` and says
  nothing about where that came from. Three runs, three identical failures,
  one bad artifact. **A reproduction that reuses a cached build is not a
  reproduction**, and the debug print that never appeared should have said so
  an hour earlier: the instrumented kernel was never in the image being
  booted.

`make iso && tests/qemu/shell-test.sh iommu` passes, and so does the whole
suite run serially. The wasted time was real and the fix in the tree is small:
the script now says which image it is booting and how old it is, so a stale one
is visible rather than inferred.

**One unrelated trap, recorded because it cost a boot.** The directory probe
grew from 228 bytes to 277 when it gained its `read`, and walked straight
through the two names sitting at offset 256 of the same page. The symptom was
the *first* `getdents64` printing nothing — a failure with no visible
relationship to the change that caused it. There is now a `const` assertion
that the code ends before the names begin, because a constant that has to stay
ahead of a length is one the compiler should be checking.
