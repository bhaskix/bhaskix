# RFC 0033: What a hosted process is — identity in ring 3, isolation in a domain

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-20** — the other half of architecture question **A6**, opened the day its first half closed. Nothing here is built |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`), kernel (`domain`, `vm` limits only), `abi` (one method, and only if a measurement asks for it) |
| **Milestone** | Phase 2 → **L1** ([RFC 0031](0031-linux-compatibility-as-an-adapter.md)'s application milestones): static binaries, BusyBox, shell utilities |
| **Depends on** | [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (compatibility is an adapter; I1–I5), [RFC 0032](0032-a-supervisor-interface.md) (the supervisor interface the adapter holds), [RFC 0017](0017-process-management.md) (`SPAWN`/`GRANT`/`START`/`BIND`/`RELEASE`), [RFC 0016](0016-capability-in-a-reply.md) (a directory *is* a badged endpoint capability), [RFC 0030](0030-packages.md) (a manifest is the reviewable list of authority) |

---

## Summary

**A Linux process is a record in `bin/linuxd`, bound one-to-one to a Bhaskix domain.** The record
holds everything Linux means by "process" — pid, parent, credentials, working directory, descriptor
table, process group — and **none of it is authority**. The domain holds the address space, the
threads and the resource envelope, and *is* the isolation. Identity lives in ring 3 because identity
is a Linux concept; isolation lives in the nucleus because isolation is the product.

Four consequences follow, and each is a decision this RFC is asking for:

1. **One domain per hosted process.** A Linux thread is a Bhaskix thread in that domain, which is
   what `clone` already does.
2. **A pid is invented by the adapter and is not a domain id.** It survives `execve`, which changes
   the domain. Today `getpid` answers *domain + 1*, which is both a leak and a lie about lifetime;
   this RFC replaces it.
3. **A file descriptor is a capability the adapter holds and the process names by an integer.** The
   hosted process holds nothing, which is interface I3 unchanged.
4. **`execve` needs no new kernel mechanism; `fork` needs one only if a measurement says so.**

It also names three fixed tables that L1 walks straight into. `MAX_SPACES` is **12** with **7** in
use on a full boot; `MAX_DOMAINS` is **32** with **11** occupied; a CSpace is **64** slots, of which
the adapter has spent 20 (endpoint, two pages, console, sixteen futex wakes) and reserved 32 more by
RFC 0032's *slot = 32 + domain id* scheme, leaving **12**. So on today's numbers this machine holds
**five** concurrent hosted processes, and their adapter can hold **twelve** more capabilities of any
kind — for every open file, directory and socket of all of them. A BusyBox shell with a pipeline
exceeds both.

## Motivation

[RFC 0031](0031-linux-compatibility-as-an-adapter.md) §"Unresolved questions" asked it first, and
`architecture.md` §8 has carried it as the open half of **A6** since 2026-08-19:

> **What is a Linux process, in Bhaskix terms?** One domain per process, or one domain per
> *workload* with several hosted processes inside it? The second is cheaper and weaker; the first
> makes `fork` and `execve` expensive. Decided by whoever implements L1's `execve`, with a
> measurement.

Three things make it urgent rather than tidy.

**The decision is already being made by accident.** `bin/linuxd` keys its signal dispositions and
its futex sleepers by *domain id* (`DISPOSITIONS[32]`, `SLEEPERS[16]`), and the kernel hands it a
`Domain` capability per hosted domain at CSpace slot `32 + id`. That is one-domain-per-process
already, chosen by nobody, written down nowhere, and depended on by a `FORGET` message whose whole
job is to survive the reuse of a domain id. A model that arrived as a side effect of three steps of
plumbing deserves either a document or a change.

**L1 cannot start without it.** `execve`, pipes and a `/proc` subset are L1's named requirements.
Every one of them is a question about what a process *is*: what survives an exec, what two processes
share, what a process may know about itself. None can be built by guessing.

**The cost of guessing wrong is measured in a table, not in style.** If a hosted process is a
domain, the machine holds five of them. If it is not, two Linux processes share an address space and
one can read the other's memory — which keeps *"a compromised Linux application is not a compromised
system"* true while quietly making *"a compromised Linux application is not a compromised Linux
system"* false. This RFC would rather raise a constant than lose that sentence.

## Design

### The record, and the rule above it

```text
struct Process {                  // in bin/linuxd, ring 3
    pid, ppid, pgid, sid,         // Linux identity: numbers, invented here
    domain,                       // the Bhaskix domain: isolation, one-to-one
    generation,                   // the domain's generation, so a reused id is not this process
    credentials { uid, gid, ... },// Linux permission arithmetic, never Bhaskix authority
    cwd,                          // a directory capability the adapter holds (RFC 0016)
    root,                         // a directory capability: what `chroot` already means
    descriptors[],                // index -> (capability, offset, flags)
    children[], exit_status,      // for wait()
    dispositions, alt_stack,      // already here, moved in at RFC 0032 step 7
    futex_sleepers,               // already here, arrived at step 10
}
```

**The rule this whole design turns on: nothing in that record is authority.** A pid is a number a
program prints and compares. A uid is arithmetic for a permission check the adapter performs against
capabilities *it* holds. The only fields that confer anything are the capability handles — `cwd`,
`root`, `descriptors` — and those are held by the adapter, in the adapter's CSpace, where a hosted
process cannot name them. That is interface I3, unchanged and now load-bearing.

### One domain per hosted process

| Linux | Bhaskix |
|---|---|
| process | a domain |
| thread (`clone(CLONE_THREAD)`) | a thread in that domain — what `SPAWN_THREAD` already does |
| thread group | the domain — what `exit_group` already ends |
| address space | the domain's address space |
| `RLIMIT`-shaped limits | the domain's `ResourceEnvelope` |
| pid | **not** the domain id — see below |

The alternative — several hosted processes in one domain — is priced in the table below and refused
for one reason: two processes in one domain share a page table, so one can read the other's memory.
Linux's own isolation between processes is the thing an application expects, and a compatibility
layer that silently does not provide it is worse than one that refuses the workload.

### A pid is invented, and outlives its domain

`getpid` answers **domain + 1** today. Two things are wrong with it, and neither showed up while a
hosted program was a self-test that never called `execve`:

- **It leaks a Bhaskix identifier into a hosted program.** A hosted process learning which domain it
  is contradicts nothing yet — it cannot name a capability with it — but it hands a foothold to
  anything that later takes a domain id as an argument, and it is the kind of leak that is cheap to
  remove now and expensive to remove after software depends on the number.
- **It pins a pid to a domain lifetime.** `execve` replaces the image of a *running* process, and
  `START` refuses a domain that has any threads (`syscall.rs`: `threads_in_domain(target) != 0` →
  `SlotUnavailable`). So an exec must build a **new** domain — and if pid is domain id, the pid
  changes, which breaks `wait`, `$!`, job control and every shell that has ever been written.

So the adapter allocates pids from its own counter, monotonic and never reused within a boot, and
keeps `pid -> Process`. The domain id becomes an implementation detail of the record.

### `execve`, with no new kernel mechanism

```text
execve(path, argv, envp) from process P, in domain D:
  1. resolve `path` through P.cwd/P.root -- a capability the adapter holds
  2. read the image into a Memory object the adapter owns
  3. SPAWN a new domain D'                       (DomainControl, which the adapter must be granted)
  4. GRANT D' what the process is entitled to    (nothing, today: hosted processes hold nothing)
  5. PERSONALITY(D') = Linux                     (so its calls arrive as foreign)
  6. START(D', image)                            (RFC 0017's existing method)
  7. move the record: P.domain = D'; drop non-inheritable state (see below)
  8. end D                                       (the old image, its threads, its memory)
```

What survives, because Linux says so: **pid, ppid, pgid, sid, credentials, cwd, root, and every
descriptor without `CLOEXEC`.** What does not: memory, threads, tids, signal *handlers* (reset to
default — dispositions do not survive an exec), the alternate signal stack, and futex sleepers.

That list is the interesting part of this RFC, because it is exactly the state RFC 0032 spent ten
steps moving into ring 3. An exec is now a thing the adapter does to its own tables plus four
capability invocations. Nothing in the nucleus knows an exec happened.

**Two costs, stated before they are measured:** an exec builds an address space and loads an ELF
where Linux would reuse the page tables it has, and it consumes a domain slot and an address-space
slot for the moment both the old and new domains exist. The second is why step 3 of the
implementation plan below raises those limits before anything else.

### `fork`, staged, and the trigger for a kernel primitive written down

`fork` duplicates an address space. Bhaskix has copy-on-write in the fault path already — the boot
report says so — but nothing exposes "duplicate this space" as a capability operation, and
[RFC 0032](0032-a-supervisor-interface.md) deliberately added mechanism only when a step needed it.

**Stage 1 — fork by copying, through the interface that exists.** The adapter knows the parent's
mappings: it answers `mmap`, `munmap` and `mprotect`, so its own region bookkeeping *is* the region
list. For each region: `MAP_AT` in the child, then `COPY_IN` from the parent and `COPY_OUT` to the
child through a `Memory` object it owns. Correct, obvious, slow, and **measurable with the
instrument RFC 0031 already built**.

**Stage 2 — a generic `COPY_SPACE(source, destination)` supervisor method**, copy-on-write, added
only if stage 1's measurement is bad enough to justify it. It is generic by construction: nothing in
"duplicate an address space" is a Linux concept, which is the test RFC 0032 set for anything the
nucleus grows.

**The trigger is written down so it is not a judgement call later:** stage 2 begins when a hosted
`fork` of a process with a working set above **one megabyte** costs more than **ten times** what the
same fork costs on Linux on the same emulated machine, or when a real L2 workload spends more than
five per cent of its wall clock in `fork`. Whichever comes first, with the number in the record.

### Descriptors: a capability the adapter holds, an integer the process names

A directory or an open file is a **badged endpoint capability to the filesystem service**
([RFC 0016](0016-capability-in-a-reply.md)); a socket is a badged endpoint to `bin/tcpd`
([RFC 0027](0027-a-sockets-api-worth-the-name.md)). So a descriptor table is an array of capability
handles, held by the adapter, indexed by the small integers Linux uses.

- **`dup`/`dup2`** copy an index; they do not derive a capability.
- **Inheritance across `fork`** copies the indices; the child's row names the same capability. Where
  a right must narrow — a read-only inheritance, later — it is a `derive`, and the child's row names
  the derived one, which is what makes revocation transitive on the parent's.
- **`CLOEXEC`** is a flag on the row, honoured at step 7 of `execve`.
- **`close`** drops the adapter's handle, which is what makes the service's own bookkeeping right.

**The hosted process never sees a slot number**, and that is the whole of I3: fd 3 is an index into a
table in ring 3, not a CSpace slot. A hosted program that guesses an integer guesses an index into
its *own* row of a table it does not own.

**This is where the adapter's CSpace runs out**, and the number is in the motivation: 64 slots, of
which slot 0 is the endpoint, 1 and 2 are pages, 3 is the console, 4–19 are the futex pool, and
32–63 are reserved by the *base + domain id* scheme RFC 0032 step 3 chose. Twelve free slots is not
a descriptor table. The implementation plan replaces the fixed base+id scheme with an allocated one
and raises `CSPACE_SLOTS`, which costs one pointer per slot in a per-domain array.

### Pipes, and why they are not a kernel object

A pipe joins two hosted processes. Both are served by the same adapter, which already holds a
`Memory` object per hosted domain's needs and sixteen notifications it may signal. So a pipe is a
ring buffer in the adapter with two descriptor rows pointing at it, and a blocked reader is a
`BLOCK_ON` reply — the mechanism [RFC 0032](0032-a-supervisor-interface.md) step 10 built for
`futex`, used unchanged.

Nothing in the nucleus learns what a pipe is. That is the point: a pipe between two Linux processes
is a Linux concept, and the moment it becomes an `Endpoint` the kernel is holding state for a dialect
it does not interpret.

**The exception, written down now so it is not discovered later:** a pipe whose two ends are in
*different workloads*, or between a hosted process and a native program, is not this. That is an
endpoint, it is authority, and it is refused until an RFC asks for it.

### `wait`, and the death of a domain

`bin/sup` already does the whole of `waitpid`: `BIND` on a `Domain` capability asks to be signalled
with a notification the caller holds when that domain ends, and `RELEASE` reaps it. So the adapter
binds one of its notifications per hosted domain, a domain ending becomes a signal, and `wait4`
becomes a `BLOCK_ON` on that notification with the exit status taken from the record.

**And the ordering is not optional, which `bin/sup` learned first:** the bind must happen *before*
the `START`, because the kernel refuses a watch for an event that has already happened — a
short-lived child can be gone before its supervisor gets round to watching, and a bind afterwards
would be a wait that never ends. For `fork` that means the child's watch is established between
`SPAWN` and `START`, in that order, or a process that exits immediately is never reaped.

**The exit status is the adapter's**, because Linux's encoding of it — the low byte for a signal,
the high byte for a status, the core-dump bit — is Linux's. What the kernel reports is an `Ending`.

### `/proc`, narrowly

L1 wants a `/proc` subset. What it may contain is decided by one rule: **nothing that names a
Bhaskix object.** `self/`, `<pid>/`, `cmdline`, `environ`, `maps` (from the adapter's own region
list), `stat`, `status`, `fd/` as the adapter's indices. Not a domain id, not a capability slot, not
a physical address. A `/proc` that leaks the domain id would hand back exactly the identifier this
RFC removes from `getpid`.

### Credentials, and the sentence they must keep true

`uid`, `gid` and the supplementary set are numbers in the record. The adapter performs Linux's
permission arithmetic with them, and then performs the operation with **the capability it holds** —
so a hosted process that becomes uid 0 has changed a number in ring 3 and gained nothing. That is
RFC 0031's second thesis (*Linux UID 0 is not Bhaskix authority*) restated as an implementation
rule, and it is what its Test 3 arm will assert once a uid exists to test.

### Concurrency, failure, and `unsafe`

**Concurrency:** unchanged and deliberately boring. The adapter has one thread and answers one
request at a time, so every table here is `static mut` with the justification already written in
`bin/linuxd` — the kernel gives a server exactly one outstanding reply, so there is no second caller
inside these functions. The moment that stops being true — more than one adapter thread — every table
in this document needs a lock, and that is written here as the trigger.

**Failure:** out of domains, out of address spaces, out of CSpace slots and out of pids are all
`EAGAIN` or `EMFILE`/`ENFILE` — Linux answers a caller can act on. A hosted process that cannot
`fork` must be told, not stalled. Out of *memory* is the envelope's refusal, which is `ENOMEM`.

**`unsafe`:** none in the nucleus. In the adapter, the same two shapes that exist today: borrows of
its own single-threaded tables, and reads and writes of its own pages.

## Step 2's record (2026-08-20): the record exists, in fifteen host tests and no wiring

**`personality/src/process.rs`: 15 tests, zero `unsafe`, and nothing calls it.** A booting machine
behaves exactly as it did — which is the point of building the arithmetic before the plumbing, and
the reason this crate exists at all.

**Four decisions became code, and each is now a test rather than a paragraph.**

- **A pid is never a domain id and never reused within a boot.** Linux reuses pids because it wraps
  at `pid_max`; this hands out a fresh one until the counter would wrap and then answers `EAGAIN`. A
  reused pid is a `kill` delivered to whoever inherited the number, which is the oldest race in
  Unix, and a machine that has started four billion hosted processes can be rebooted.
- **Pids start at 2.** Zero is `wait`'s "any process in my group" and a `kill` target meaning the
  whole group; 1 is `init`, which this system does not have and should not pretend to be — a program
  that finds itself pid 1 may reasonably start reaping orphans.
- **A record is found by domain *and generation*.** A domain id is reused; a lookup by id alone
  would answer for whoever holds the slot now. This is the third place in this project to need that
  pairing, after the kernel's `FORGET` message and the thread-counter bug before it.
- **What survives an exec is a list, and the list is the test.** Pid, parent, group, session,
  credentials, working directory, root, and every descriptor without `FD_CLOEXEC`. The domain is the
  thing that changes.

**The exec sweep hands back what it closed, and that is a type telling the truth.** Each closed row
carried a handle the adapter holds a capability behind, so `Table::close_on_exec` takes a callback
rather than returning a count: an exec that dropped the rows silently would leak one capability per
closed descriptor for the life of the adapter, and this makes forgetting it a compile error rather
than a boot six weeks later.

**Orphans go to nobody, not to `init`.** Linux gives them to pid 1; inventing one here would be a
process that exists only to make a sentence true. A parent of zero means nothing will read that
status, and the adapter may drop the record — which is what `discard` refuses to do while a parent
is still there to read it.

**`Processes` is deliberately not `Copy`**, alone in this crate: a `Process` carries a whole
descriptor table, so the table is tens of kilobytes and a stray dereference would compile into a
memcpy of all of it on a machine whose kernel stack is sixty-four kilobytes. A build-time assertion
bounds the size, so a field added later is priced when it is written.

**Six of the fifteen tests were watched red** by deliberate edits: pids reused, the exit status
returned unshifted, a status collected twice, the generation check deleted, `wait(0)` read as "any
child", and the exec keeping its `CLOEXEC` descriptors. Each failed exactly the test that names it —
and the first three also failed *other* tests, which is what a table with real invariants does.

**What this step deliberately did not do:** signal dispositions are still `bin/linuxd`'s own table
keyed by domain rather than a field of this record. Moving them in is a later step; the reset that
an exec owes them is commented at the place it will go, because a handler surviving an exec would
call an address that is no longer code.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **One domain per *workload*, several Linux processes inside it** | Two processes in one domain share a page table, so one can read the other's memory. It keeps "a Linux compromise is not a system compromise" and quietly loses "a Linux compromise is not a compromise of every other Linux process", which is what an application actually expects. Cheaper in domain slots, and the slots are a constant | A workload whose processes are mutually trusting by construction *and* a measured slot shortage that raising the constants cannot fix |
| **pid = domain id** (what the code does today) | Breaks `execve`, which must change the domain because `START` refuses a domain with threads; leaks a Bhaskix identifier; and ties a Linux lifetime to a Bhaskix one | Never. The two lifetimes are genuinely different |
| **The descriptor table in the hosted domain's CSpace**, as capabilities it cannot name | More faithful in one sense, but it makes the nucleus hold per-fd state for a dialect it does not interpret — the exact thing RFC 0032 spent ten steps and a ratchet removing. It would also hand a hosted process CSpace slots, which is I3's line | A second personality wants the same mechanism, so it stops being Linux-shaped state |
| **A kernel `fork` primitive first** | It is mechanism added before a measurement, which is the mistake RFC 0032 avoided by adding methods only when a step needed one. Stage 1 is buildable today and produces the number | The staged trigger above fires |
| **`execve` in place, via a new `REPLACE_IMAGE` method** | It needs the kernel to tear down an address space *with the caller's own thread running in it*, which is a harder guarantee than "make a new domain and end the old one" for no gain the record cannot give | A measurement shows domain creation dominates exec cost, and the teardown can be shown safe |
| **A pipe as an `Endpoint`** | The kernel would hold state for a Linux concept; and endpoints are authority, where a pipe is a buffer | The two ends are in different workloads, which is a different feature and needs its own RFC |
| **One adapter per hosted workload** rather than one per machine | Would relieve the CSpace ceiling and shrink the blast radius of an adapter bug, at the cost of a table naming which service serves which domain on the hot path — which RFC 0032 refused with a trigger ("a second dialect") | The CSpace ceiling cannot be raised far enough, or the blast radius argument wins on its own |

## Impact on existing design documents

| Document | What becomes wrong |
|---|---|
| [architecture.md](../architecture.md) §8 | **A6**'s row says *what a hosted process is* stays open. If this is accepted it is closed, and A6 with it |
| [RFC 0031](0031-linux-compatibility-as-an-adapter.md) | Unresolved questions **1** (what a process is) and **2** (where the descriptor table lives) are answered here; **3** (does a hosted process ever get a notification) is still open and is restated below |
| [RFC 0005](0005-linux-abi-compatibility.md) | Its Tier 1 surface assumes a descriptor table without saying whose. This RFC says whose |
| [security.md](../security.md) §1 | **T11**'s note lists what the adapter holds. Files, directories and pipes join that list, and the note must say that an adapter compromise now reaches every hosted process's files — which is *more* than it reached on 2026-08-20 |
| [roadmap.md](../roadmap.md) | L1's row can name its prerequisites precisely once this is settled |
| `bin/linuxd`'s package manifest | The finding from RFC 0032 step 10 — the grammar cannot say *write-only* or *sixteen* — becomes pressing, because the list is about to grow |

## Security implications

**New authority: yes, and it is the adapter's.** To serve `execve` the adapter needs
`DomainControl` — the authority to create domains — and a directory capability to resolve paths
against. Today it holds one endpoint, three pages, a write-only console and sixteen notifications.
After L1 it holds the power to make domains and to reach a filesystem subtree. That is a real
increase and this RFC will not describe it as anything else: **a compromised adapter would reach
every hosted process's files and could create domains within its own envelope.** What it still could
not do is name a capability it was not given — no ambient root, no device, no memory outside what it
holds.

**Reachable without a capability: nothing new.** A hosted process still holds none and can name
none. Every number this RFC adds to a hosted process's world — pid, uid, fd — is an index or an
invention.

**New parsers for untrusted input: yes.** Paths, `argv`/`envp` vectors, and the ELF images an
`execve` loads. The ELF loader is already fuzzed (RFC 0005's campaign, 2026-08-13); the path and
argument decoders are new host-fuzz targets and are named in the testing plan.

**Scope movement:** none out. **T11** stays in scope and its note grows.

## Performance implications

Three numbers, none of which exists yet:

1. **`execve` cost**, split into domain creation, ELF load and record transfer. Compared against the
   same binary started by `bin/sup`, which is the native shape of the same act.
2. **`fork` by copying**, per megabyte of working set — the number that decides whether stage 2
   happens.
3. **The descriptor path**, one `read` through the adapter versus the same read by a native program
   through `bin/vfsd`: the containment cost for files, measured the way RFC 0031 measured it for
   system calls (the instrument is already there and already prints).

Raising `MAX_SPACES`, `MAX_DOMAINS` and `CSPACE_SLOTS` costs static kernel memory and nothing else:
an `AddressSpace` is three words plus a heap-allocated region map, a domain slot is a table entry,
and a CSpace slot is one `Option<SlotRef>`. The bill is arithmetic and belongs in the step that
raises them.

## Testing plan

- **Host:** the process table, pid allocation, descriptor inheritance and `CLOEXEC` semantics, the
  exec-survival list, and Linux's exit-status encoding are pure logic in `personality/` — host tests,
  zero `unsafe`, no QEMU.
- **QEMU:** one gate per act, each negative-armed. A hosted program that `execve`s and **keeps its
  pid**; a `fork` whose child sees its own memory change and the parent's not; a pipe that blocks a
  reader until a writer writes; a `wait` that returns the child's status; a process that cannot read
  another hosted process's memory (RFC 0031 Test 1, in the shape only two hosted processes can fund).
- **Real hardware:** nothing here needs it.
- **Fuzz:** the path decoder and the `argv`/`envp` vector reader, both host targets, both reading
  process-supplied pointers.

## Unresolved questions

1. **Does a hosted process ever get a `Notification`?** RFC 0031's question 3, still open. `epoll`
   wants one and this RFC does not need one, so it is deferred to whoever builds `epoll` — with the
   note that answering yes puts a Bhaskix concept inside the Linux boundary and should be argued,
   not slipped in.
2. **Sessions, controlling terminals and job control.** L1's shell utilities need `setsid` and
   `tcsetpgrp` to be *something*. The record has the fields; what a controlling terminal **is**, when
   the console is a capability and not a device file, is a question this RFC leaves open.
3. **How many adapters.** One per machine today. The CSpace ceiling and the blast radius both argue
   for more; the hot-path lookup argues for one. Decided by the first of those to bite.
4. **`vfork` and `posix_spawn`.** Both exist to avoid `fork`'s copy, which is stage 1's whole cost.
   If stage 2 lands, both become ordinary; if it does not, `posix_spawn` may be the cheaper thing to
   make fast.
5. **What a hosted process is told about CPUs and memory.** `sched_getaffinity` already answers four
   as a stated narrowing; `sysconf`, `/proc/meminfo` and `getrlimit` will each need the same
   decision, and the envelope is the honest source for all three.

## Implementation plan

Ordered so that each step is provable on its own, and front-loaded with the limits, because every
later step consumes them.

1. **This document**, plus the corrections it names in `architecture.md` §8, RFC 0031's unresolved
   list and the tracker. ✅ *Delivered 2026-08-20 — six documents, and two of them said something
   that had been quietly wrong for longer than this RFC has existed: RFC 0005's Tier 1 paragraph
   names `getpid`, `execve` and `wait4` without ever saying whose descriptor table or whose pid,
   and `roadmap.md`'s L1 row listed prerequisites that are all downstream of a decision nobody had
   taken. `security.md` §1's T11 states what an accepted RFC 0033 would add to the adapter's
   authority **before** it is added, which is the only time such a note is worth anything.*
2. **The record, host-tested, with nothing wired.** `personality/` grows a process table: pids,
   parents, groups, descriptors, the exec-survival list, the exit-status encoding. Pure logic, zero
   `unsafe`, no behaviour change on a booting machine. ✅ *Delivered 2026-08-20 — see the record
   below.*
3. **The three limits, raised and measured.** `MAX_SPACES` 12 → 32, `MAX_DOMAINS` 32 → 64,
   `CSPACE_SLOTS` 64 → 128, and the adapter's `base + domain id` slot scheme replaced by an
   allocated one. The bill printed in the boot report beside the counts that already print. Gated by
   the existing "each program in its own address space" check, extended to say how many are free.
4. **`getpid` stops being the domain id.** The adapter allocates pids; the record maps them. One
   gate: two hosted processes have different pids and neither equals a domain id.
5. **`execve`**, end to end: `DomainControl` granted to the adapter, a path resolved, an image
   loaded, a new domain started, the record moved, the old domain ended. The gate is **pid
   stability** — a hosted program that execs and reports the same pid on both sides.
6. **Descriptors and `/proc/self/fd`**, with `open`, `close`, `dup`, `read`, `write` on files, and
   inheritance across exec.
7. **Pipes**, and a blocked reader woken by a writer — `BLOCK_ON`, unchanged from step 10.
8. **`fork` by copying**, with the measurement that decides whether stage 2 exists.
9. **`wait4` on domain death**, over `BIND` and the notification pool.
10. **The `/proc` subset**, and the leak test: nothing in it names a Bhaskix object.
