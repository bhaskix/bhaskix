# RFC 0016: A capability in a reply, and a filesystem that is not the kernel

| | |
|---|---|
| **Status** | 📝 **Draft.** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/cap`, `kernel/syscall`, ABI, `services/vfs`, a new filesystem service |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) — closes the *full VFS* bullet |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (what a reply is), [RFC 0009](0009-shared-memory.md) (revocation), [RFC 0013](0013-service-framework.md) (placement), [RFC 0015](0015-filesystem.md) (the filesystem this moves) |

---

## Summary

RFC 0015 built a filesystem and left it in the nucleus. Not by preference — twice, at two different
steps, the same wall was hit from two different sides:

- **Step 4** put name resolution in the kernel because a service had no way to give a caller a
  capability, and a directory a program holds *is* a capability.
- **Step 6** could not lend a reader a cached frame for the same reason, plus a second one: nothing
  owned the lending, so nothing could end it.

This RFC proposes the one mechanism both were missing, and then moves the filesystem out. On the way
it turned up two things that were not known before it was written: badges can be forged, and the
block service cannot write — so the journal, whose whole subject is what reaches a disk, has never
reached one.

The mechanism is **a reply that carries a capability**. A server answering a `Call` already holds
exactly the right authority for this and nothing more: a one-shot reply capability naming the one
thread that asked, valid only while it waits. Handing something back along it is narrower than any
alternative, and it is the same shape as `FILL`, which this system already has and already trusts.

It also proposes a fix to something found while writing this: **badges were forgeable.** Any holder
of a capability with `DERIVE` could derive another with a badge of its choosing. Every use of a badge
to say *who is calling* or *which object* was unsound, and the design below depends on badges
entirely — so the fix was not a follow-up, it was step one, and it is **already done**: see the
implementation plan.

---

## Motivation

### The kernel parses a disk

`bhaskix-fs` is 3,467 lines, and every one of them is linked into ring 0. It reads inodes, directory
entries, block pointers and a journal out of bytes that came off a device. RFC 0013's whole argument
was that a service in the nucleus can do anything and a service in a domain can do what it holds; a
filesystem parser is the most hostile-input-facing code in this system and it is currently the least
contained.

The crate has no `unsafe` and a mutation harness, which is why this is a design fault and not an
emergency. It is still the wrong place for it.

### A service cannot give a caller a capability

This is the actual blocker, and it is worth stating plainly because it explains two steps of RFC 0015
that otherwise look like laziness.

There are two ways today for a capability to reach a domain, and neither fits:

- The **kernel** installs it, at domain creation or from a self-test. That is why `Directory`
  capabilities are minted by `user_shell` at boot and resolved by `kernel/src/namespace.rs`: it was
  the only way to have one at all.
- **`GRANT`**, which needs a `Domain` capability for the recipient with `WRITE` rights. A filesystem
  service holding that over every client could install anything into any of them, kill them, or
  reach their address spaces. Solving "hand back a file handle" by handing the server the client is
  not a solution.

So a directory capability cannot come from the thing that owns directories.

### A cached frame cannot be lent

RFC 0015 step 6 built the cache and stopped at its headline claim. Handing a reader a capability to a
cached frame needs, in order: a capability to *one* frame (a capability to the cache exposes every
other block in it, including other files' data and every piece of metadata touched); a guarantee the
frame is not evicted while lent, or the holder silently reads somebody else's block; and a moment at
which the lending ends, so the pin can be released and the capability revoked.

The last one is the reason this is the same problem. "When does the lending end" is *when the client
lets go of its file handle*, and only the thing that issued the handle can see that. Today nothing
issues handles, because nothing can.

### Badges were forgeable

Found while drafting this, verified rather than assumed, and since fixed — step 1 below. The
derivation that found it:

```
insert_root(Endpoint, ALL, badge = 0)      // the kernel's master capability
  └─ derive(rights = ALL, badge = 0xaaaa)  // what a client is given
       └─ derive(rights = ALL, badge = 0xbbbb)   // what the client can do for itself → Ok
```

`Arena::derive_owned` set the badge to whatever it was passed and checked only that the parent had
`DERIVE`. `INVOKE`'s `DERIVE` passes `arg1` straight through from userspace, and the shell holds its
service endpoints with `Rights::ALL`, so any program in ring 3 could do this.

What it currently buys an attacker is small — there is one interesting client — and that is luck
rather than design. `Rights::NONE`'s own documentation says a capability with no authority is
"useful as a proof of identity without power, **which badges make meaningful**", and the filesystem
service already keys per-caller state on the badge, so a second client could take over the first's
accumulated path. More to the point: everything below assumes a badge is a statement *the granter*
made, and right now it is a statement the holder can make.

---

## Design

### 1. Badging is one-way

A capability with badge zero is a **master**: deriving from it may set any badge. A capability that
already carries a badge may only be derived with **the same** badge.

```
derive(parent, rights, badge):
    if parent.badge != 0 and badge != parent.badge:
        refuse: InsufficientRights
```

Rights stay monotone as they already are, so a client can still delegate — narrower rights, same
badge. What it cannot do is change who the badge says it is. That is the whole property, it is three
lines, and the test that proves it is the derivation above with the last step required to fail.

Badge zero therefore means "unbadged", which is already how the kernel uses it: every root capability
it mints has badge zero, and every client capability is a badged derivation of one. Nothing changes
for existing code except that a path nobody was using stops working.

### 2. `HAND`: a reply that carries a capability

A new method on an `Endpoint` capability, deliberately modelled on `FILL` and checked in the same
order and for the same reasons:

```
HAND      arg0 = the server's own slot, holding the capability to give
          arg1 = rights for the copy
          arg2 = badge for the copy
          arg3 = the slot in the *caller* to install it in
      ->  the slot it landed in
```

Three checks, none of which the server can supply for itself:

1. **The endpoint capability proves this thread is a server** of that endpoint. Resolved from the
   caller's own CSpace, as every invocation is.
2. **The reply obligation says which caller.** The kernel already records `reply_to` for the thread;
   a thread that is not mid-request has nobody to hand anything to and is refused. This is what makes
   the authority one-shot and specific — it reaches the one thread that asked, while it is waiting,
   and nothing else.
3. **The capability is one the server holds**, with `Rights::GRANT`, derived under the monotonicity
   and badge rules above. A server cannot conjure authority it does not have.

The destination slot is named by the *caller*, in its request, not chosen by the server or by the
kernel — the same rule `DERIVE` and `OPEN_AT` follow, for the same reason: a program's CSpace is its
own to arrange, and the shell keeps slots empty on purpose.

**Why a reply and not a message.** A server that could hand a capability to any domain it could name
would need to name domains. A server answering a call names nobody: the kernel already knows who is
waiting. The authority is therefore bounded by something the server did not choose and cannot
extend.

### 3. `Directory` and `File` stop being kernel object kinds

With `HAND`, a directory handle can be what it should have been: **a badged endpoint capability to
the filesystem service.** The badge is the service's handle for that directory. The service keeps the
table. The kernel stops knowing what an inode is.

This deletes `ObjectKind::Directory`, `ObjectKind::File`, `method::OPEN_AT`, `Status::NoSuchName`,
`Status::BadName` and all of `kernel/src/namespace.rs` from the kernel, and moves the rules they
enforce — one component, no separators, no `..`, generation checked — into the service, where they
are ordinary code with ordinary tests rather than syscall-path code.

The properties RFC 0015 step 4 established do not change and must not:

- A name outside the directory held is unreachable, and answers the same as a name that exists
  nowhere.
- A malformed name answers differently from a missing one, because otherwise the guard is
  indistinguishable from no guard.
- A handle that outlived its directory resolves to nothing.

The last one gets *better*: today the kernel checks a generation packed into a capability's identity,
and a manufactured stale capability is needed to test it. In the service, a handle whose generation
no longer matches is a lookup miss in a table the service owns, and `remove` produces one for real.

### 4. The filesystem becomes a service in a domain

`services.toml` gains a third entry, `placement = "domain"`. The service holds:

- an endpoint of its own, from which every directory and file handle is derived;
- an endpoint capability to the **block service** (`bin/blkd`), which is where its `Store` goes —
  the trait RFC 0015 step 6 introduced exists exactly so this substitution is a new implementation
  and not a rewrite. **`bin/blkd` cannot write.** It answers `block::READ` and `block::CAPACITY` and
  nothing else. RFC 0015's step 1 called for "`READ` and `WRITE`"; only `READ` was built, and nothing
  since has needed the other half — which means the journal, whose entire subject is what reaches a
  disk, has so far only ever reached memory. `block::WRITE` is a prerequisite of this RFC and is the
  first thing step 3 below builds;
- the `Memory` objects its page cache lives in.

`tools/check-placements.sh` then enforces what it enforces for `console` and `vfs`: that the crate
builds with no kernel in the build at all, and depends on nothing but the ABI and the service
framework. That is the check that makes "it is out of the kernel" a fact rather than a claim, and it
is why `bhaskix-fs` must stop being a dependency of `bhaskix-kernel` rather than merely being unused
by it.

**What the kernel keeps, and why that is not a cheat.** The nucleus still reads the initrd, because
it has to load `bin/vfsd` before there is anything to ask. That reader is `ustar` over an image the
bootloader placed in memory — a fixed archive, not a device, not written to, and not attacker-chosen
in any threat model where the bootloader is trusted. It is a boot loader, and it should be described
as one rather than as a filesystem.

### 5. Lending a cached frame

The cache's frames become **one one-page `Memory` object each**, rather than one object of N pages.
This is forced: `shared::create` allocates frames individually and they are not contiguous, so a
single object cannot be handed out a page at a time — and handing out the whole thing is the
disclosure this is trying to avoid.

Then:

- **Lend.** The service derives a read-only capability to the frame's object and `HAND`s it back. It
  marks the frame pinned; a pinned frame is never chosen for eviction.
- **Return.** The client says it is done, or the service revokes. Revocation is RFC 0009's, which
  already unmaps a domain that is running — the machinery exists and is tested.
- **Reclaim.** A service that needs the frame back revokes and unpins. A client that was reading gets
  its mapping removed underneath it, which is exactly what RFC 0009 says happens and what its tests
  already cover.

**The failure to be afraid of** is not a crash, it is silence: a frame reused while lent hands one
program another program's data with nothing to see. So the test is not "lending works" but *a lent
frame is never the frame chosen for eviction, at every eviction*, in the same shape as RFC 0015's
interruption harness.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| The kernel asks the service from inside `OPEN_AT` | A syscall that blocks inside the kernel on another domain, on the syscall path, under no lock discipline that survives it. And the kernel would *still* have to know what a directory is, so it buys nothing. | Never. This is the option that looks cheapest and is worst. |
| The service holds a `Domain` capability for each client and uses `GRANT` | It works today with no kernel change, and it is a rout: a `Domain` capability with `WRITE` lets the holder install anything into that domain. Solving "hand back a handle" by handing the server the client. | Never. |
| Keep `Directory`/`File` as kernel object kinds; add a `Filesystem` capability the service derives them from | Tempting, and it fits the derivation tree well — revoking the filesystem takes every handle with it. But the kernel keeps the identity model, and it must then trust inode numbers the service supplies. A capability system where the kernel understands inodes is a kernel with a filesystem in it. | If badges turn out to be unusable as object handles for a reason not yet seen. |
| Fix badge forgery by giving clients capabilities without `DERIVE` | A client that cannot delegate is not usable in a capability system: every program that wants to hand a narrower capability to a child would have to ask a service to do it. Solves the symptom by removing the feature. | Never. |
| A `Frame` capability for a cached page, instead of a one-page `Memory` object | `Frame` exists and is simpler. But it names a physical page with no owner and no revocation story, and lending needs revocation more than it needs simplicity. | If `Frame` grows the same revocation semantics, at which point they are the same thing. |
| Copy the block into the client's memory instead of lending a frame | Honest, simple, already possible with `FILL`. It costs a copy per block and a round trip; RFC 0015 measured a round trip at ~5,000 cycles. For small reads it may genuinely win. | Measurement. This should be the fallback for reads under some size, and the size should be measured rather than guessed. |
| Leave the filesystem in the nucleus and accept it | It is 3,467 lines of disk parser in ring 0. Every other subsystem has been moved out on a weaker argument than this one. | Never. |

---

## Impact on existing design documents

- **[RFC 0013](0013-service-framework.md)** — its placement table gains a third service, which is
  what it was built for. No change to the framework itself; if one is needed, that is a finding
  about RFC 0013 and should be recorded as one.
- **[RFC 0015](0015-filesystem.md)** §*A page cache in shared memory* says a reader "is given a
  read-only capability to those frames". This RFC makes that one frame, and explains why the plural
  was wrong. §*Resolution is relative to a directory a caller holds* keeps its claims and changes
  where they are enforced.
- **[docs/security.md](../security.md)** §1 — the trusted computing base shrinks by a filesystem.
  The paragraph listing what runs in the nucleus becomes wrong and must be rewritten, not amended.
- **[docs/memory.md](../memory.md)** — one-page `Memory` objects and pinning are new; whatever that
  document says about `Memory` objects being sized by their creator needs the pinned case added.

---

## Security implications

Per [docs/security.md](../security.md) §1:

**This closes a hole.** Badge forgery is live today and this fixes it. That is the part of this RFC
that should not wait for the rest of it.

**It shrinks the TCB.** A hostile disk currently reaches a parser in ring 0. Afterwards it reaches a
parser in a domain that holds an endpoint, some memory, and nothing else — which is the entire
argument of RFC 0013 applied to the subsystem that most needs it.

**It introduces new authority: `HAND`.** Worth stating precisely what a holder of it can do. A thread
that (a) holds an endpoint capability, (b) is mid-reply to a caller, and (c) holds a capability with
`GRANT`, can install a *no-stronger* copy of that capability into a slot **the caller named in its
own request**. It cannot choose the recipient, cannot act outside a call, cannot exceed its own
rights, and cannot change a badge it did not mint. The failure mode to test for is the second
condition: a server that could hand something while not answering anybody would be a server that
picks its recipient.

**Fuzz target.** The filesystem parser already has one and it moves with the code. The new one is the
service's message loop: a client sending malformed, out-of-order and interleaved requests against
handles it does and does not hold. That is a target this project does not have an equivalent of yet.

---

## Performance implications

**Every name resolution becomes a round trip.** ~5,000 cycles (~2 µs), measured in M7-06. A path of N
components is N round trips unless the service resolves a whole path in one call — which RFC 0015
already proposed and which this makes load-bearing rather than an optimisation.

**Frame lending is what pays for it.** A reader that maps a cached block does not copy it and does
not make a round trip per block. The comparison to measure is not "before and after" but *lend versus
copy*, at several sizes, because the copy path is cheaper below some block count and nobody knows
where.

**To measure:** boot time; the shell's `cat` of a file already in the cache; a read of a file that is
not; and the crossover size between lending and copying. A performance claim without a benchmark is a
hypothesis, and the crossover is the one this RFC is least sure of.

---

## Testing plan

**On the host**, which is most of it:

- The badge rule: deriving with a different badge from a badged parent is refused; with the same
  badge, or from a master, it is allowed. The negative test is the exact derivation chain in
  *Motivation* above, with the last step required to fail — it passes today and must stop.
- The service's namespace rules, which are the RFC 0015 step 4 tests moved out of the kernel and
  turned from boot gates into ordinary tests: a name outside the directory held, a separator, `..`, a
  stale handle.
- The service's handle table: a handle it never issued, a handle issued to a different client, a
  handle used after `remove`.

**In QEMU:**

- The shell reaches a file through a capability **a service handed it**, and the boot report says
  which service. The gate that matters is the negative one: the shell cannot reach a name outside the
  directory it holds — the same claim RFC 0015 step 4 gates today, which must survive the move
  unchanged, because a property that quietly weakened during a refactor is the thing this whole
  process exists to catch.
- A client cannot forge a badge, demonstrated from ring 3 rather than argued.
- `HAND` from a thread that is not answering anybody is refused.
- A lent frame is not evicted: the service reports its eviction choices, and a gate asserts a pinned
  frame is never among them.
- `check-placements.sh` builds the filesystem service with no kernel in the build.
- **The kernel gets smaller.** `bhaskix-fs` leaves `bhaskix-kernel`'s dependency list, and the
  `unsafe` budget and the kernel's line count both go down. These are gates, not observations: a move
  that did not shrink the nucleus did not happen.

**On hardware:** nothing specific to this RFC beyond what M1-17 already blocks on.

---

## Unresolved questions

- **Does `HAND` belong on the endpoint, or on the reply?** It is written above as a method on the
  endpoint capability because that is what `FILL` does and the checks are identical. But the
  authority being exercised is really the *reply's*, and a `Reply` capability is a thing this system
  already has. Making it a method on the reply would be more honest and would make the "not answering
  anybody" case a lookup failure rather than a check. Decide before implementing, not after.
- **What ends a lending?** Explicit release by the client is simplest and is a promise a client can
  break. Revocation when the handle goes needs the service to observe the handle going, which it
  cannot today. The likely answer is that the service revokes whenever it wants the frame and the
  client must cope — which RFC 0009 already requires of everybody — but that makes every lent
  mapping a fault waiting to happen and the cost of that should be understood first.
- **Where does `mkfs` live?** It links `bhaskix-fs` and runs on a developer's machine. Once the crate
  is not in the kernel, nothing about the arrangement changes, but the workspace's story about which
  crates are `no_std` and which are tools gets one more entry and should be written down once.
- ~~**Does the block service need `WRITE`?**~~ Answered while writing this, and it is not an open
  question but a gap: `bin/blkd` has no write path, RFC 0015's step 1 said it would, and the journal
  has therefore only ever been exercised against memory. Folded into step 3.

---

## Implementation plan

Five steps. The first is independent of the rest and should not wait for it.

1. ~~**Badging becomes one-way.**~~ ✅ **Done, ahead of the rest of this RFC**, because it closes a
   live hole and depends on nothing else here. Three lines in `derive_owned`, `CapError::BadgeNotMonotone`
   (answering userspace with the same status as the other two derive refusals, so a caller cannot
   probe which rule stopped it), host tests for both directions, and gates from ring 3.

   Two places in the tree **demonstrated the hole as a feature** and had to be rewritten: the kernel's
   capability self-test asserted that a re-badged derivation kept the new badge, and `user/probe`
   derived itself a badge of its own choosing from raw ring 3 with the comment "the service sees the
   *new* badge, which is how a derived capability is distinguishable from its parent". It is not, and
   it must not be — what distinguishes a derived capability is its rights and its position under the
   parent, which is what the revocation in that same test already showed.

   Both halves are gated, and neither is worth anything alone: a program delegates its capability
   under the same badge and the call arrives, **and** it asks for one under a badge it invented and is
   refused. A kernel that refused every derivation would pass the second on its own, so the
   over-strict version was watched failing too.
2. **`HAND`.** The method, its three checks, and the negative tests for each — including a server
   that is not answering anybody, and a server handing something it holds without `GRANT`. Proved by
   a throwaway service that hands back a capability to a memory object, before any filesystem depends
   on it.
3. **`block::WRITE`, and then the filesystem service in a domain.** Two halves, and the first is
   owed from RFC 0015 step 1: the block service gains a write over RFC 0009's bulk path, and the
   journal is exercised against a **device** for the first time — including the interruption harness,
   which has until now stopped a store backed by an array. Then the filesystem service's `Store`
   becomes messages to `bin/blkd`. No namespace yet: the criterion is that it mounts the same image
   and reads the same bytes the kernel reads today, from the same disk, with the kernel not linking
   `fs`.
4. **Directory and file handles.** The namespace moves out; the kernel's `namespace.rs`,
   `ObjectKind::Directory`, `ObjectKind::File` and `OPEN_AT` are deleted. The RFC 0015 step 4 shell
   gates must pass **unchanged** — that is the point of them.
5. **Lending a cached frame**, with pinning and the eviction gate. Last, because it is the only step
   whose failure is silent, and it should be built when everything under it is already trusted.
