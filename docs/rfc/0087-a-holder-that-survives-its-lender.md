# RFC 0087: A holder that survives its lender

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-30 — built and gated, armed red both ways.** A space its builder opts in turns a revoked shared region into scratch memory instead of a refusal; `bin/tcpd` is opted in, and stops dying when a program whose rings it holds exits. The acceptance call is the project lead's. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`vm`, `shared`), mm |
| **Milestone** | Phase 2 — [RFC 0086](0086-the-motivating-workload.md)'s services under load |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (shared memory), [RFC 0022](0022-capability-in-a-call.md) (gifts, and a lender's death ending the lending), [RFC 0044](0044-revocation-that-reaches-the-mapping.md) (revocation that reaches the mapping), [RFC 0082](0082-a-domains-own-memory-is-its-own.md) (a domain's memory is charged to it) |

---

## Summary

A service that maps memory other programs lend it dies when one of them
does: the lender's objects are revoked with it, the mappings go, and the
service's next touch of that memory is a refused fault that ends the service.
This RFC lets **whoever builds an address space** mark it to survive: in such
a space, a shared region revoked out of it becomes *anonymous* — its next touch
is a fresh zeroed frame charged to the space's owner — instead of a refusal.
The lender's frames are unmapped first and are never reachable. `bin/tcpd` is
the first space so marked.

## Motivation

**The defect, measured.** On networked boots `bin/tcpd` was being killed after
`bin/tcpc` exited: a late connection — an early attempt by the boot harness's
inbound driver, whose `SYN` `slirp` kept retrying after the host had given up —
arrived with sixteen bytes, took the listener's ring pair, and `tcpd` wrote
them into rings revoked with `tcpc`'s domain. The kernel refused the access and
tore `tcpd` down. The same fault, at the listener's own receive ring, is in two
serial logs taken on 2026-09-30 from the tree before RFC 0086 step 2 and in ten
CI job logs; every one of those boots passed, because nothing asked whether
`tcpd` was still alive.

**What it means beyond a harness.** Any program that gifts `tcpd` its rings
and exits takes the machine's TCP service down with the next packet on that
pair — every other program's connections with it. A service cannot choose
when its clients die, and the stream rings are the clients' memory by design
(RFC 0020, RFC 0022): a program pays for its own buffers, and a client cannot
spend the service's memory.

## Design

### The opt-in, and who holds it

`AddressSpace` gains `scratch_on_revoke`, false by default, and
`keep_revoked_as_scratch()` to set it. **Only whoever builds the space sets
it** — for `tcpd`, the kernel in `tcp_domain_entry`. No method lets a program
opt itself in: a program that could would turn every revocation it suffers
into memory it keeps writing, and a lender taking a loan back is exactly the
moment that must not be softened by the borrower.

### What happens at revocation

`shared::revoke` walks every mapping of the object. For each, **before** its
pages are unmapped, it asks the holder's space to turn the region into scratch;
a space that did not opt in says no and is left exactly as before.
`RangeMap::orphan_shared` does the change in place: the region starting at that
address, and only if it is shared memory **of that object**, becomes
`Backing::Anonymous` with the same range and protection, `copy_on_write` and
`populate` cleared. Nothing is inserted, removed or allocated, so it cannot
fail half-way, and one object's revocation can never blank another's region.

Then the pages are unmapped and shot down as before, and the object is
destroyed. The next touch in the opted-in space is an ordinary demand-paging
fault on an anonymous region: a fresh frame, zeroed by the allocator's
hygiene, charged to the space's owner (RFC 0082).

**The order, and the window it opens.** The space table (rank 0) is taken and
released before the shootdown (rank 4), `unmap_roots`'s order. Between the two
the region says anonymous while the table still maps the object's frame —
which is still the object's, freed only after every mapping is gone — so a
touch in that window reaches memory that is still valid, and the next one
after the unmapping is served fresh.

### The argument this answers

`vm::service_fault` refuses a fault on a shared region, and its comment says
why: servicing it *"would hand the faulting code a fresh frame at the address
it was just revoked from: a revoked mapping silently replaced by blank memory,
which is worse than either keeping it or refusing it"*, and *"this arm is what
stops the stale entry becoming an accidental grant."* Both still hold for
every space that did not opt in, and the arm is unchanged. For one that did:

- **Not a grant.** The lender's frames are unmapped before anything else and
  are not what is handed out; the holder receives memory it pays for, which it
  could have mapped itself.
- **Not silent.** `vm::scratched()` counts every region turned, and the boot
  prints it.
- **Not accidental.** It happens only where the space's builder chose it.

### What `tcpd` does with a dead pair

Nothing, deliberately. A connection whose rings became scratch carries on into
memory nobody reads — its client is gone — and when it leaves the table its
pair returns to the listener as any pair does, so a later connection may take
it and serve into scratch too. That costs at most every armed pair's pages
(32 pairs × 8 pages), charged to `tcpd`. **Dropping a dead pair instead needs
a way to ask whether a capability is still alive**, and no method answers that
without changing something (`DERIVE`, `REVOKE` and `DELETE` are all there is);
adding one is a kernel interface of its own, left for when a second reason to
want it appears.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Loans outlive the lender: a gifted object survives its owner until the holder lets go | Reverses RFC 0022 step 3's decision, and a dead domain's pages stay readable by the holder for as long as it keeps them | the holder must keep the lender's *data*, not just survive |
| Service-owned rings, lent to clients | Reverses RFC 0020/0022's program-owned rings; any client could make `tcpd` spend its memory; the largest protocol change | a service's memory can be charged to its clients |
| `tcpd` checks a pair is alive before each touch | A revocation between the check and the write still kills `tcpd`; narrows the window without closing it | never alone — it is a hygiene step on top of a guarantee |
| Hand revoked-region faults to the service to handle | A fault channel for services is a much larger mechanism, and `tcpd` would have nothing better to do with the fault than this | a service needs to *know* its lender went, synchronously |
| Let a program opt its own space in | A borrower could soften every revocation it suffers | never |

## Impact on existing design documents

- **`kernel/src/vm.rs`, `service_fault`'s comment** — kept, with a dated note
  saying the rule still holds and naming the one opt-in exception.
- **`docs/security.md` §2 rule 3** — unchanged in substance: revocation still
  removes the mapping before anything else, from every holder. What an opted-in
  holder has at that address afterwards is its own new memory.
- **RFC 0022 step 3** — unchanged: a lender's death still ends the lending.
  The holder no longer dies of it, which that step never promised either way.

## Security implications

- **No new authority.** The opted-in holder gains memory at an address it
  already had a region at, charged to its own envelope — what `MAP_AT` would
  have given it. It gains nothing of the lender's.
- **The opt-in is not reachable from ring 3.** Only kernel code building a
  space can set it.
- **A lender can still take its loan back, instantly and completely** — the
  mapping goes before the object does, as RFC 0044 requires.

## Performance implications

One `with_space` per mapping revoked, and one region rewritten in place for an
opted-in holder: nothing on any path that does not revoke. A holder pays one
fresh frame per page it touches after a revocation, bounded by the regions it
had.

## Testing plan

- **Host:** `RangeMap::orphan_shared` — range, protection and count preserved;
  another object's region, a non-start address, and anonymous or device memory
  all refused and unchanged. The refusal test was watched failing with the
  object check removed.
- **Kernel self-test:** an owner lends one object to an opted-in holder and a
  plain one, the object is revoked, and `commit_page` — the servicing a fault
  does — must serve the first with a frame **that is not the lent one** and
  refuse the second, with exactly one region turned.
- **Boot gate:** that self-test's line, and **`bin/tcpd` alive at the end of
  the boot** — `Domain "tcp" is gone` fails it. Armed: with `tcpd`'s opt-in
  removed, the first networked boot killed `tcpd` and the gate went red.

## Unresolved questions

1. **A liveness query for capabilities**, so a service can stop re-arming a
   pair whose owner is gone — see *What `tcpd` does with a dead pair*. The
   trigger is the first service that must *know*, rather than merely survive.
2. **Which other services should opt in.** `bin/linuxd` maps its hosted
   processes' memory through `COPY_*` rather than gifted regions today; a
   service that maps a client's gift for longer than one call is the trigger.

## Implementation plan

1. `RangeMap::orphan_shared` and its host tests. ✅ 2026-09-30
2. `AddressSpace::keep_revoked_as_scratch` / `revoked_to_scratch`, the
   `SCRATCHED` count, and the hook in `shared::revoke`. ✅ 2026-09-30
3. `tcpd` opted in by `tcp_domain_entry`. ✅ 2026-09-30
4. The self-test, the `tcpd`-alive gate, both armed. ✅ 2026-09-30
