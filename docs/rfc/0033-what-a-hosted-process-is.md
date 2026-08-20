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

## Step 3's record (2026-08-20): four limits, a latent aliasing bug, and 269 KiB

**The machine holds twenty-five spare address spaces where it held five.** `MAX_SPACES` 12 → 32,
`MAX_DOMAINS` 32 → 64, `CSPACE_SLOTS` 64 → 128 — and a fourth this RFC had not counted:
`MAX_CAPABILITIES` 1,024 → 4,096, because **a descriptor is a capability in that arena**, and 64
descriptors across fifteen hosted processes is 960 of the thousand that existed. A ceiling found by
walking toward it rather than by being hit.

**The bill is printed on every boot rather than estimated here:**

```text
fixed tables   spaces 32 x 40B, domains 64 x 1736B, cspace 128 slots, arena 4096 x 40B
               -- 269 KiB of static kernel memory
```

Sizes and not counts, because `size_of` is what moves when a field is added to what a table holds —
the change most likely to make one of these expensive without anybody noticing. The line is gated
on being *said*, not on a threshold: a limit on static memory would be a gate on a linker's
arithmetic, but a report line that quietly stopped printing would take the pricing with it.

### The bug the raise would have introduced, and the assertion that will not let it back

`domain::LINUX_DOMAINS` — the bitmask the syscall entry reads once per call to decide whether a
domain's calls are foreign — was a **`u32`, masked with `% 32`**, sized by a coincidence with
`MAX_DOMAINS` rather than by construction. Raising the table to 64 without widening it would have
made **domain 33 alias domain 1**: a native domain's system calls read in Linux's dialect and
handed to the adapter, or a hosted domain's answered natively. The mask is a `u64` now, and a
`const` assertion refuses to build a table wider than the bits — verified by setting `MAX_DOMAINS`
to 128 and watching `assertion failed: MAX_DOMAINS <= u64::BITS` stop the build.

**The same shape existed in ring 3**, where `bin/linuxd` sized its signal-disposition table at 32
and indexed it `% 32`. Two hosted domains sharing a row of signal handlers is the same class of
fault with a worse blast radius. Both sides now read **one** constant — `abi::limits::MAX_DOMAINS`
— and the kernel asserts its own against it, because a constant that exists twice is a constant
that will disagree once.

### The adapter's handles are allocated now, and the kernel says where

`slot = 32 + domain id` needed no table on either side and reserved **half a CSpace against a
machine running two hosted programs**. Since a descriptor is a capability the adapter holds, that
reservation is exactly what L1 would have run out of.

The kernel takes the lowest free slot at or above a floor above its fixed grants, installs the
handle there, and sends a message — `HANDLE_METHOD`, `u64::MAX - 3`, beside `FORGET` — naming the
domain and the slot. Ordering is what makes it safe: the message is an ordinary call made by *the
hosted thread itself*, so it is answered before the foreign call that provoked it, and on a reused
domain the `FORGET` goes first so an adapter clearing its row does not clear the slot it is about
to be told. The old incarnation's slot is handed back before the new one is allocated — a stale
handle is authority over a domain that no longer exists.

**Armed** by having the kernel install the capability and *not* say where: the memory, clone and
futex self-tests all went red at once, which is what "this program can answer questions about
numbers and nothing else" looks like from the outside.

### A fault of a known shape, seen once, and what its own instrument says about it

The first full suite after the raise produced a kernel fault in the `console=nucleus vfs=nucleus`
placement: a hosted thread reached ring 3 in **somebody else's address space**, faulting on an
instruction fetch at a garbage address. Fourteen repeats of that lane since — five immediately and
eight in a controlled run — have been clean, and it has not recurred in any other lane.

**It is a fault this project has met before and fixed.** On 2026-08-13 the cause was found in
`vm::install` — the address space was loaded before the thread recorded owning it, so a preemption
inside that window left `finish_switch` calling `enter_space(0)` and the previous `CR3` in place. The
fix (record before loading) was verified at **0 faults in 50 boots** against a prior rate of one in
ten, and an exit check was added at the paths back to ring 3.

> **Correction, 2026-08-20 (same day).** This section first said the tracker's *"the uncovered one is
> an exception return to user mode"* still stood, and that the capture pointed at that missing fourth
> check. **It is not missing.** `check_user_space(3)` is called from three places in `trap.rs` — the
> serviced page fault, the fault handed to the personality, and the faulting-domain end — and has
> been since RFC 0005 step 4. The tracker sentence was written before that and was read here as
> current. What follows is what the evidence actually supports.

**The capture says the check was clean while the thread was not, and that turned out to be a blind
spot in the check itself.** Its counter reads `exits to ring 3 with the wrong space: 0 (0 not
checked)` — all four instrumented paths clean — while the faulting thread was demonstrably in the
wrong space. Reading `check_user_space` explains it: it compares a thread's *recorded* root against
`CR3`, and when the recorded root is **zero** it returned **silently** — no counter, no trace. A
thread resumed with no space recorded is exactly what the switch replay showed, and exactly how
`enter_space(0)` leaves somebody else's `CR3` loaded. The instrument could not see the shape of the
fault it exists for.

**Both halves are closed now**, in a change of their own beside this step: a return to ring 3 by a
thread owning no address space is counted, traced with its site and thread, reported on every boot,
and **fails the boot**. So does a wrong space — which was printed in red and failed nothing, so a
detector that fired would have reported into an empty room. Armed: forcing every user return to look
rootless, and forcing every comparison to look wrong, each turned the boot red.

**What this step claims and does not claim.** It does not claim the raise caused it: the shape,
the counter and the recorded open gap all point elsewhere, and the rate is not what a new
deterministic breakage looks like. It does not claim the raise is innocent either: more concurrent
address spaces is more exposure to a wrong-`CR3` window, and that is an honest consequence of raising
the limit. What is written down is the observation, the evidence, and the next instrument — the
fourth exit check, on the exception return — which belongs to its own change with its own
verification rather than bolted onto this one.

### What did not move

The gate for the free count is **at least eight**, not "more than before": eight is a shell
pipeline's worth of hosted processes, and a future service quietly eating the headroom is caught
there rather than by the eleventh program faulting in a space that could not be installed. Armed by
putting `MAX_SPACES` back to 12 — `found 7 used and 5 free`, which is the sentence this step
exists to stop being true.

## Step 4's record (2026-08-20): a pid a coincidence cannot explain

**`bin/linuxd` holds the process table now, and `getpid` answers out of it.** The record built in
step 2 is wired: a hosted domain's first foreign call admits a process, `getpid` returns its pid,
and the kernel's `FORGET` — "this domain slot is somebody else now" — retires it.

**The gate is stronger than the one this RFC asked for.** "Two hosted processes have different
pids" would pass on almost anything; "neither equals a domain id" is a coincidence away from
meaningless, since both are small numbers. What is gated instead is a property the old scheme could
not have satisfied:

```text
linux pid      pid 2 in domain 2; pid 3 in domain 2;
               distinct pids across 2 hosted programs, 1 of which shared a domain slot
```

**Two programs ran in the same domain slot and were given different pids.** Under `pid = domain + 1`
they were both pid 3, because the number was a function of the slot. Both halves are demanded —
`distinct`, *and* at least one pair sharing a slot — because "distinct" alone would pass on a boot
where no two programs happened to share one, which is a property of the boot rather than of the
personality. **Armed** by putting `domain + 1` back: `REUSED pids across 2 hosted programs`.

**An arm that did *not* go red, reported rather than quietly dropped.** The adapter keeps an
incarnation counter per domain slot so that a stale record cannot be found after the slot is reused.
Removing the bump changed nothing any test could see — because the record is also *dropped* on
`FORGET`, and the drop always succeeds while no hosted process has a parent to read its status. The
counter is not decoration; it stops being unobservable the moment `discard` can refuse, which is the
moment `fork` gives a process a parent. Written at the code and here rather than left as a green
tick over an untested line.

**Two things this step deliberately leaves wrong**, because fixing either is a later step and
pretending otherwise would be worse:

- **`gettid` still answers the kernel's thread id plus one**, so a hosted process's main thread has
  a tid that is not its pid. Linux guarantees they are equal, and `tgkill(tgid, tid)` is where that
  matters. The fix belongs with the record's thread list, not here.
- **The exit status handed to a retiring record is `0`**, invented, because the `FORGET` message
  does not carry the domain's `Ending`. Nobody can read it — no hosted process has a parent — so it
  is a lie with no reader today and a bug the day `wait4` lands.

## Step 5's record (2026-08-20): a hosted program execs, and keeps its pid

**A hosted program called `execve` and became another program, in another domain, with the same
pid.** Three witnesses, none of which can produce another's answer:

```text
linux exec     a Linux program execed: its own domain ended and the program it became ran in another
linux exec     pid 3 kept across an exec: domain 2 became domain 3
execed pid 3                                    <- printed by the program that was exec'd
```

The kernel watched the execing domain's thread count reach zero. `bin/linuxd` reported, out of its
own page, which pid it kept and across which two domains. And the program that replaced it asked
`getpid` **in the new domain** and printed the answer. The gate demands that the last two name the
same number and that the two domains differ — which a pid derived from a domain could not satisfy,
and which is exactly why step 4 came first.

### The sequence, and the one line worth reading twice

```text
SPAWN        a domain          (DomainControl, granted at boot; the envelope allows sixteen)
PERSONALITY  Linux             (so its calls arrive at the adapter)
MAKE_SPACE                     (new — see below)
MAP_AT       code, stack       (read-execute and read-write, eagerly)
COPY_OUT     the image
SPAWN_THREAD at the entry
exec_into    the record        (same pid, new domain)
reply END_DOMAIN               (which is what ends the caller's domain)
```

**Nothing here can kill a domain**, and nothing needed to. RFC 0017 deliberately left "a supervisor
may kill its child" out, and RFC 0032 did not add it. What ends the old domain is the *reply*: the
caller is told to end, and the kernel does it to the thread that asked. An `execve` is therefore
the calling program's own last act — which is precisely what `execve` is.

### One kernel method this plan did not have

`MAKE_SPACE`, on a `Domain` capability. A freshly created domain has **no address space**: every
other way to get one is to be a thread inside the domain and have the kernel build it, and there is
no thread until the supervisor starts one — which it cannot do until the pages that thread will run
in exist. The circle is real, and one generic method breaks it. Nothing about "this domain needs an
address space" is a Linux concept, which is the test RFC 0032 set for anything the nucleus grows;
it is refused on a domain that already has one or that has threads, and it answers **nothing** — a
page-table root is a fact about the machine that no capability handed over.

### The narrowing this plan did not anticipate: there is one path

`execve` resolves **`/bin/execed`** and answers `ENOENT` for everything else. There is no file
surface yet — that is step 6 — so the program it execs is compiled into the adapter, forty-two
bytes of hand-assembly that ask their pid and print it. **A path with one answer is still a path**:
the argument is read out of the caller's memory through a capability, compared, and refused when it
does not match. What is *not* real yet is resolution, `argv`, `envp`, and anything an ELF loader
would do. Each is named here so that none of them is discovered later as a surprise.

### Three mistakes, all of them arithmetic, all found by the instrument

- **The record was moved after its key was invalidated.** The first version bumped the old domain's
  incarnation *before* looking the record up, so the lookup missed, admitted a **fresh** record, and
  exec'd that — the new program printed a pid one higher than the program it replaced. The gate
  caught it as `kept='3 2 3', console says 'execed pid 4'`, which is the two-witness design doing
  the only job it has.
- **The exec record was written into the scratch area.** It sat at `REPORT_AT + 8 * 32`, which is
  where `copy_in` stages its bytes, so every copy after the exec overwrote it and the kernel printed
  the tail of a path as a pid (`pid 15 ... domain 750815947819084146`). It is past the scratch bound
  now, and placed *relative* to it so that moving one moves the other.
- **`drain_into` is named for its sink, not for consumption.** It reads from the object's beginning
  every time; a "fix" that assumed the previous read had consumed 256 bytes made the kernel print
  `mmap` record zero as a pid.

**Armed**, both halves: replying with a value instead of `END_DOMAIN` left the execing domain alive
and the self-test could not conclude; skipping `exec_into` gave the new program a fresh pid and the
gate named both numbers.

### What it cost

The adapter's `unsafe` budget rises 50 → 56 and **not one of those lines is in `execve`**: a domain
created, given an address space, mapped, filled and started, entirely through capability
invocations, dereferencing nothing. The kernel's rises 1,510 → 1,525, of which thirteen are the
exec *probe* — a hosted program has to be built by something not on the far side of the boundary it
tests — and two are the read of the adapter's record.

**`security.md` §1's T11 grows by one line**, as its own note said it would: the adapter holds
`DomainControl` now, so a compromise of it can create domains within its envelope and do to them
everything a supervisor can. A domain it creates is still **empty** — every authority it will ever
hold is one the adapter passes from what it holds, and there is no ambient root.

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
   ✅ *Delivered 2026-08-20 — four limits, not three; see the record below.*
4. **`getpid` stops being the domain id.** The adapter allocates pids; the record maps them. One
   gate: two hosted processes have different pids and neither equals a domain id. ✅ *Delivered
   2026-08-20 — with a stronger gate than the one written here; see the record below.*
5. **`execve`**, end to end: `DomainControl` granted to the adapter, a path resolved, an image
   loaded, a new domain started, the record moved, the old domain ended. The gate is **pid
   stability** — a hosted program that execs and reports the same pid on both sides. ✅ *Delivered
   2026-08-20 — with one narrowing this plan did not anticipate and one kernel method it did not
   have; see the record below.*
6. **Descriptors and `/proc/self/fd`**, with `open`, `close`, `dup`, `read`, `write` on files, and
   inheritance across exec.
7. **Pipes**, and a blocked reader woken by a writer — `BLOCK_ON`, unchanged from step 10.
8. **`fork` by copying**, with the measurement that decides whether stage 2 exists.
9. **`wait4` on domain death**, over `BIND` and the notification pool.
10. **The `/proc` subset**, and the leak test: nothing in it names a Bhaskix object.
