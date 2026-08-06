# RFC 0015: A filesystem that can be written to, and a namespace that is not ambient

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-06.** Two of its four open questions are decided by acceptance and recorded below; one is deferred to process management, which owns it; one stays open until step 6, where it needs something `memory.md` cannot yet say. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `services/vfs`, a new block service, a new `fs` on-disk format, ABI (`fs::` methods) |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) — the *full VFS* bullet |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (bulk transfer), [RFC 0013](0013-service-framework.md) (the filesystem is a service in a domain), [RFC 0014](0014-driver-framework.md) (the block driver, and the virtqueue both drivers share) |

---

## Summary

The filesystem today is a `ustar` archive handed to a service at entry. It cannot be written to, it
has one mount, and every path resolves from an ambient root that no caller had to hold anything to
reach.

This proposes three things that are usually described as one and are not:

1. **A namespace that is not ambient.** A caller resolves a path *relative to a directory it holds*,
   because "the root" is exactly the sort of authority a capability system is supposed to have
   abolished and this one has quietly kept.
2. **A writable filesystem with a journal**, on a block device reached through a service — with the
   crash-consistency claim tested by cutting the machine off at every write rather than argued for.
3. **A page cache in shared memory**, because a domain round trip costs ~5,000 cycles (M7-06) and a
   filesystem that pays that per block is a filesystem nobody will measure twice.

Each is separable and the order matters: the namespace is a design decision, the journal is the hard
one, and the cache is an optimisation that must not be done first.

---

## Motivation

### The root is ambient, and that is a hole in the model

`vfs::open(b"etc/hostname")` resolves from a static. Any program holding the filesystem endpoint
reaches every file, and the only thing bounding it is that `..` is refused — a check that exists
because the backend is flat and would have to become a real traversal check the moment it is not.

Everything else in this system was made to work the other way. A domain names memory by a slot in
its own CSpace; a driver names a device by a capability the kernel minted; RFC 0013 removed
`Request::caller` so a service could not *name* a caller at all. The filesystem is the last place
where holding one capability grants everything of a kind.

### There is no way to write anything down

The machine cannot save a byte across a reboot. That is not a missing feature so much as a missing
half of the system: every mechanism built so far — domains, capabilities, services, drivers — exists
to run programs, and nothing those programs do can outlive them.

### The block device is reachable by exactly one program

`bin/blkd` drives a device and reads sector zero into its own memory. Nothing can ask it for a
block. It is a driver without an interface, which was correct for RFC 0014's purpose and is the
first thing in the way here.

### Sixteen bytes a round trip is not a filesystem

RFC 0009 opened the bulk path and M6-18 measured it: 228 bytes move in one round trip through shared
memory against fifteen by message. M7-06 then measured what a domain costs — ~5,000 cycles, about
+48% — and M7-13 put both a filesystem and a block driver in domains. A read that crosses two
domain boundaries per block, in 16-byte messages, would be slower than the disk.

---

## Design

### Resolution is relative to a directory a caller holds

A new object kind, `Directory`, and one new method on it:

```
OPEN_AT   the capability register = the Directory to resolve in
          arg0..2 = the name, as a chunk
          arg3    = the slot to put the result in
      ->  that slot, with IS_DIRECTORY set if what landed in it is one
```

*(Amended in step 4 from the sketch this RFC was accepted with, which put the directory in `arg0`
and left no room for a destination. The directory belongs in the capability register, where every
other invocation puts the object being invoked; `Chunk::pack` already carries a spare word for the
destination, which is what its `extra` argument is for. The caller names the destination rather than
the kernel choosing a free slot, for the same reason `DERIVE` does: a program's CSpace is its own to
arrange, and the shell keeps slot 2 empty on purpose. A name longer than one chunk is **refused**,
not truncated — a truncated name opens a different file and does it silently. A multi-chunk `OPEN`
is future work and is noted below.)*

A program is given a `Directory` capability at boot, as it is given a console and a filesystem
endpoint today. It can reach what is under it and nothing else.

**A correction from step 4, to the sentence this paragraph used to end with.** It said containment
needs no check on `..`, because a name that leaves the directory resolves to nothing there is a
capability for. The first half is true and is the point; the second half made a claim about
`..` that does not survive contact with a test. `..` is not an entry in any directory this format
writes, so a lookup that never rejected it would simply fail to find it — and a build with the check
deleted would behave *identically* to one with it. The check therefore exists, it is explicit, and
it answers with a **different status** from a name that is merely absent:

| | |
|---|---|
| `NO_SUCH_NAME` | nothing of that name is in this directory |
| `BAD_NAME` | that is not a name this system resolves: a separator, `.`, `..`, an embedded zero, empty |

The distinction is safe to make, and it is the only one here that is. `BAD_NAME` describes the
syntax the caller used, which the caller already knows; it says nothing about what is on the
filesystem. A name that exists *elsewhere* on the same filesystem stays indistinguishable from a
name that exists nowhere, because a program that could tell those apart could map a filesystem it
holds one directory of, one question at a time.

Without the distinction the guard would be untestable, and an untestable guard in this system has
historically meant an absent one.

**Mounting is granting.** A mount point is a `Directory` capability installed in another
filesystem's namespace; there is no mount *table* in the kernel, because a table is a global and a
global is the thing being removed. `mount` becomes "give this service a capability to that
directory", which is an operation the system already has.

**What this costs.** A path with N components is N round trips unless a service can resolve several
at once. The RFC proposes resolving a whole path *within one service* in one call, and crossing a
mount boundary as a second call — so the cost is one round trip per filesystem crossed, not per
component. That is measurable and is in the testing plan.

### A block service, not a block driver

`bin/blkd` grows an endpoint and answers two methods:

```
READ   arg0 = first sector, arg1 = count, arg2 = the caller's slot holding Memory
WRITE  the same, in the other direction
```

The bulk path is RFC 0009's: the caller names memory it already holds and the service fills it. No
sector data crosses in message registers, ever.

The driver stays where it is otherwise — one device, one queue, one request outstanding — and
becoming a service is the smallest change that makes it usable by anything but itself.

### An on-disk format, and why not an existing one

A new format, deliberately small: a superblock, a bitmap of free blocks, inodes with direct and
single-indirect blocks, and directories as arrays of `(name, inode)`. No extents, no B-trees, no
extended attributes.

**Why not ext2, or FAT?** Both are well specified and both would make the *format* the work: ext2's
compatibility rules and FAT's history are large surfaces whose failure modes are not this project's
to learn. A format this kernel defines can be as small as the thing it has to prove, and the thing
it has to prove is the journal. An existing format also cannot be changed when the journal needs
something from it, which is the usual reason journals get bolted on badly.

The cost is real and should be stated: nothing else can read this disk. A tool to build and inspect
an image is part of the work, not an extra.

### The journal, which is the whole difficulty

Write-ahead. Every change is written to a log, the log is committed with a checksum, and only then
are the blocks written where they belong. After a crash, the log is replayed from the last commit.

**Metadata only.** File *data* is not journalled: a crash may lose recent writes, and must not lose
the filesystem. Data journalling doubles every write and the difference is a policy this system has
nowhere to express yet.

**The claim being made** is precisely this: *after any interruption, the filesystem mounts, and every
operation that was acknowledged before the interruption is present.* Anything weaker is not worth a
journal, and anything stronger is not true without ordered data writes.

### A page cache in shared memory

Blocks are cached in a `Memory` object the filesystem service holds. A reader that wants a cached
block is given a *read-only capability to those frames* rather than a copy: RFC 0009's revocation is
what makes that safe to hand out, and the same machinery already takes a mapping away from a domain
that is running.

**Write-back, not write-through**, with the journal deciding when a dirty page may be written home —
which is the only ordering constraint the cache has and the reason it cannot be designed before the
journal.

---

## Alternatives considered

**Keep the read-only archive and add a second, writable filesystem beside it.** Rejected: two
namespaces with different rules is the thing mount points exist to avoid, and the archive would
still be the root.

**A kernel-resident filesystem.** Rejected by RFC 0013's whole argument, and now by measurement: the
service in a domain costs ~5,000 cycles a call, and the fix for that is fewer calls with more in
them, not moving it back.

**An existing on-disk format.** Discussed above. The decision could reasonably go the other way, and
the deciding factor is that this project's value is in what it can *prove*, not in what it can read.

**No journal — `fsck` instead.** Rejected. A repair tool is a claim that damage can be detected
after the fact, which for a filesystem with no redundancy is mostly false, and it moves the
correctness argument to a program nobody runs until it is too late.

---

## Impact on existing design documents

- **`architecture.md`** — the filesystem section describes a read-only archive.
- **`security.md`** — "a program reaches what it holds a capability to" gains its most important
  case, and the ambient root is a hole that should be named there before it is closed here.
- **RFC 0013**'s `Filesystem` service grows methods; its `Bulk::fill` is the shape the block
  service's transfer should take.
- **`memory.md`** — a page cache is the first thing in this system that holds memory *speculatively*,
  and the resource envelope has no answer for it yet.

---

## Security implications

**The good, and it is the point.** Removing the ambient root is the largest single reduction in what
a compromised program can reach that this system has left to make. A program with a `Directory`
capability to `/tmp` cannot name `/etc/hostname` — not because a check refuses it but because there
is no capability that reaches it.

**What this adds.** A writable filesystem is the first thing an attacker can *change* that survives
a reboot. Everything before this was memory, and rebooting fixed it.

**What is deliberately not solved.** No permissions, no owners, no access control lists. A capability
to a directory is the authority; there is no second system on top saying who may use it. That is
consistent with the rest of the design and it means this filesystem cannot express "readable by
everyone, writable by one" — which real systems need and which should be argued in its own RFC.

---

## Performance implications

**Slower than a kernel filesystem, by a known amount.** M7-06's figures are the baseline: ~5,000
cycles a round trip, ~+48%. A read that hits the page cache is one round trip; a miss is two, because
the block service is another domain.

**What will be measured**, and the numbers to beat are in TRACKER M6-18 and M7-06:

| Measurement | Why |
|---|---|
| Round trips per `open` of an N-component path | The design says one per filesystem crossed. That is either true or the resolution model is wrong |
| A cached read against an uncached one | What the cache is for, and whether shared memory kept it to one round trip |
| Throughput writing a megabyte, journal on and off | The cost of the guarantee, stated rather than assumed |
| Time to mount after an interrupted write | Replay is on the boot path, so this is boot time |

---

## Testing plan

**On the host**, where most of this can be:

- The on-disk format: every structure round-trips, and a mutation harness over a whole image
  asserts that no single-byte corruption makes the parser panic — the standard this project already
  holds `ustar` to.
- The allocator: a block is never handed out twice, and a freed block is not readable through a
  stale inode.
- Path resolution against a mock service: a name that leaves a directory resolves to nothing, and a
  mount boundary is one call and not N.

**In QEMU, and this is the part that decides whether the journal is real:**

- **Interrupt the machine at every write.** A harness runs an operation, and re-runs it stopping the
  virtual machine after the 1st, 2nd, … Nth block write. For every N: the filesystem mounts, and
  every acknowledged operation is present. A journal whose recovery has been tested at one arbitrary
  point is a journal that has been tested nowhere.
- The same, with the writes *reordered* within a commit, because a device is entitled to.
- A full disk, a corrupted superblock, and a log whose checksum fails: each must refuse to mount
  rather than mount something.

---

## Unresolved questions

### Decided by acceptance

**The filesystem owns the cache, not the block service.** A block service caching blocks caches the
wrong thing: it does not know which blocks are a file and which are the journal, and it would keep
the log warm at the expense of data. The filesystem knows, and it is also the side that must hand
out read-only capabilities to cached frames — which it can only do for memory it owns. The block
service therefore keeps filling memory the caller names, exactly as step 1 proposes, and the memory
it is named is the cache.

**A `Directory` capability names an inode *and a generation*, and deleting bumps the generation.**
A stale capability then resolves to nothing rather than to whatever took the slot. This is not a new
mechanism: `MemoryId` and `NotificationId` in this tree are both an index and a generation for the
same reason, and the alternative — refusing to delete a directory somebody still holds — makes
deletion depend on who is watching.

### Deferred, to the RFC that owns it

**Where path resolution begins for a program holding no `Directory` capability.** Boot grants the
first one, the way it grants a console and a filesystem endpoint today, and that is enough to build
every step below. The general answer is "the thing that hands a new program its namespace", which is
a supervisor — RFC 0013 declined to propose one and process management is where it belongs. Naming
it here would be this RFC deciding something it does not have to.

### Raised by step 4

- **A name is at most one chunk — sixteen bytes.** Longer names are refused rather than truncated,
  which is the safe failure, but the format allows twenty-seven. An `OPEN_AT` that accumulates a
  name across chunks the way the filesystem service accumulates a path is the fix; it is not needed
  by anything yet and would have been built untested.
- **Resolution is a function call, not a message.** Step 4's `Directory` capabilities resolve in an
  image the kernel mounted, so the kernel parses the filesystem — which is what RFC 0013 moved out.
  That is deliberate for one step, because a namespace built on a read-only image cannot destroy
  anything while it is being got right, and none of the design above changes when the backing store
  moves behind the block service. It does mean the `unsafe`-free `fs` crate is now called from the
  nucleus, and step 6 has to move it back out.
- **Rights on a directory are the rights on what it opens.** A lookup gives the new capability the
  rights the directory was held with, and never more. There is no way yet to hand out a directory
  that may be *listed* but not *opened through*, which is a distinction a supervisor will want.

### Still open

**How large may the cache grow?** The resource envelope counts frames a domain owns, and a cache
that grows to fill it starves the domain of everything else. Nothing in this system can currently
say "this memory is reclaimable", and inventing that at step 6 — where it is needed — is better than
guessing at it now. It may want a change to `memory.md` rather than to this design.

### The decision most likely to be wrong, and how it will announce itself

A new on-disk format rather than an existing one. If step 2 turns out to be larger than step 5 —
if writing the *format* costs more than writing the *journal* — then the format was the work after
all, and this was the wrong call. That comparison is the trigger, it is cheap to notice, and it is
written down here so that noticing it is not a matter of remembering to.

---

## Implementation plan

Six steps. The first three are worth having even if the rest is never built, which is the test of
whether the order is right.

1. **The block service.** `bin/blkd` grows an endpoint, `READ` and `WRITE` over RFC 0009's bulk
   path. The criterion is that the kernel's own driver can be asked for a sector and gets the same
   bytes it reads directly.
2. **The on-disk format, on the host.** Structures, the allocator, and the mutation harness, with a
   tool that builds an image. No kernel involvement at all — this is the part that can be proved
   without a machine.
3. **A read-only mount of that format**, beside the archive, to prove the format works before
   anything writes to it.
4. **`Directory` capabilities and `OPEN_AT`.** The namespace change, on the read-only filesystem
   where a mistake cannot destroy anything. ✅ Done — see the amendment and the correction above.
5. **Writes, and the journal.** With the interruption harness, because the journal's claim is the
   only thing here that cannot be checked by looking.
6. **The page cache**, last, because the journal decides when a dirty page may go home.
