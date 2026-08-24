# RFC 0032: A supervisor interface — the authority to hold a program, held as a capability

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-20** — all ten steps delivered and gated, and the number the RFC exists to move reads **0**: the nucleus interprets no Linux syscall number. Drafted 2026-08-19 as the prerequisite [RFC 0031](0031-linux-compatibility-as-an-adapter.md) §5's relocation turned out to need, before any of it was built — which is the order this project's rules ask for and the order the personality itself did not follow |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`vm`, `syscall`, `sched`), `abi`, userspace (`bin/sup`, later `bin/linuxd`) |
| **Milestone** | Phase 2 — what unblocks the roadmap's last bullet, and Phase 3's container work after it |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (all authority arrives as a capability argument), [RFC 0009](0009-shared-memory.md) (`Memory` objects, and the creation method it specified and nobody built), [RFC 0017](0017-process-management.md) (`Domain` capabilities, `SPAWN`/`GRANT`/`START`), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (the adapter this exists to let out of the nucleus) |

---

## Summary

**A program that holds another program needs authority over it, and today that authority
does not exist as a capability — it exists as being the kernel.** `START` lets a supervisor
hand a child an image and let go. Nothing lets it read the child's memory, change the
child's mappings, or set a thread's registers. So anything that must do those things has to
*be* kernel code, which is exactly why the Linux personality is in the nucleus and why
[RFC 0031](0031-linux-compatibility-as-an-adapter.md) §5's relocation cannot start.

This RFC adds that authority as **six methods on a `Domain` capability**, and one new shape
of reply. None of them is a Linux concept: a native debugger, a checkpointer, a container
runtime and a Linux adapter all want the same six. The trade is stated plainly and is the
whole of what a reviewer should argue with:

> **The nucleus grows a supervisor interface so that the personality can leave it entirely.**
> Roughly 250 lines of generic mechanism in, so that ~3,240 lines of Linux ABI can go out —
> and, more importantly, so that the largest untrusted-input parser this project will ever
> contain stops running in ring 0.

## Motivation

### What is actually blocking

[RFC 0005](0005-linux-abi-compatibility.md) has said since it was drafted that the
personality belongs in a service domain. Step 9 of its implementation established that this
is no longer a preference: Tier 2 (sockets, `epoll`) **cannot be built in the nucleus at
all**, because `bhaskix-sock` is a ring 3 client and a hosted `connect()` must become a
capability call to `bin/tcpd` that kernel code cannot make.

So the personality must move. Moving it means asking what an adapter in ring 3 would need,
and the answer is a short list of things no capability currently confers:

| The adapter must | Today that is | Where |
|---|---|---|
| read a hosted process's `struct sigaction`, `sockaddr`, futex word | `copy_from_user`, which resolves through `CR3` | `arch/x86_64/src/uaccess.rs` |
| write a signal frame onto a hosted thread's stack | `copy_to_user`, likewise | `kernel/src/signal.rs:172` |
| redirect a thread to its signal handler, and restore it | direct `TrapFrame`/`SyscallFrame` field writes | `kernel/src/signal.rs:179`, `:226` |
| service `mmap`/`munmap`/`mprotect` | `vm::with_active`, which is `CR3`-gated | `kernel/src/syscall.rs:1865` |
| service `clone` | `record_pending_clone` + `take_pending_clone` + `cloned_thread` | `kernel/src/domain.rs:654`, `kernel/src/lib.rs:2195` |
| park a thread on `FUTEX_WAIT` | `WaitQueue::wait_until` on a kernel static | `kernel/src/syscall.rs:2137` |

Every row is a *mechanism* the kernel must keep. Every row's *policy* is Linux and must go.
This RFC is the line between those two columns.

### Why not simply leave it

`security.md` §1 **T11** — a hostile Linux application inside a compatibility domain — is
in scope and is **not mitigated today**. The first half of its mitigation holds structurally
(a hosted process holds no capabilities and cannot name one). The second half does not: a
bug in the translator is a kernel bug, because the translator is the kernel. That is the
gap this RFC exists to let somebody close, and doing nothing means Tier 1's file surface
lands in ring 0 too, at which point the adapter starts holding per-process state and moving
it gets an order of magnitude dearer.

### Why this is not a back door

The obvious objection: *a capability that reads another domain's memory is exactly the
ambient authority this project deleted.* It is not, and the difference is checkable rather
than rhetorical:

- **It is held, not ambient.** The authority is a `Domain` capability carrying `WRITE`, the
  same thing `START` and `PERSONALITY` already demand. A program that was not given one can
  do none of this, and there is no way to obtain one by asking.
- **It is scoped to what you made.** In practice a supervisor holds capabilities to the
  domains it created — `SPAWN` returns one — and to nothing else.
- **It is revocable, transitively and immediately**, like every capability here. Revoking a
  supervisor's `Domain` capability ends its reach into that domain before the call returns.
- **It is one-directional.** The hosted domain gets nothing. Its CSpace stays empty, which
  is RFC 0031's interface I3 and the reason a compromised hosted process still cannot name a
  capability, whatever its adapter can do.

`ptrace` is still refused, and the distinction is worth stating because it looks similar.
`ptrace` lets *a process that merely shares a uid* attach to another. This lets *a holder of
a capability to a domain* operate on it. The first is ambient authority with a permission
check; the second is authority in hand.

## Design

### The six methods, on a `Domain` capability

All require the capability to carry `Rights::WRITE`, refused with `InsufficientRights`
otherwise. Numbering continues from `PERSONALITY = 58` in `abi/src/lib.rs`.

| # | Method | Arguments | Answers |
|---|---|---|---|
| 59 | `COPY_IN` | memory slot, offset, address in target, length | bytes copied |
| 60 | `COPY_OUT` | memory slot, offset, address in target, length | bytes copied |
| 61 | `MAP_AT` | address, pages, protection | 0, or the address |
| 62 | `UNMAP_AT` | address | 0 |
| 63 | `PROTECT_AT` | address, pages, protection | 0 |
| 64 | `SPAWN_THREAD` | entry, stack, argument | the new thread's id |

**The copies name a `Memory` object, never a raw buffer**, and this is the shape that keeps
the interface honest. A supervisor asking to read a child's memory hands over an object it
already owns for the bytes to land in — so the kernel is never asked to copy between two
addresses it must separately validate, and the supervisor never names an address in its own
space at all. It is `DRAIN`/`FILL`'s discipline (`kernel/src/syscall.rs:1376`) pointed at a
domain instead of at a caller.

**Protection is `bhaskix_mm::Protection`, so `W^X` stays unrepresentable.** A supervisor
cannot ask for writable-and-executable because the type has no such value — the same reason
a hosted `mmap` cannot, and it costs nothing to inherit.

**Every operation is bounded and refuses rather than truncates.** A copy that runs past the
object or past a mapped region is refused whole. A `MAP_AT` over an existing region is
refused, not silently replaced: an adapter that thought it was making a new mapping and
actually replaced a live one is a bug that presents as memory corruption in the hosted
program, a long way from its cause.

### `SET_REGISTERS`, and why it is on a thread rather than a domain

Signal delivery redirects a thread to its handler; `rt_sigreturn` puts it back. Both are
"overwrite this thread's saved user register frame", and a domain is the wrong unit — a
process has many threads and a signal lands on one.

This RFC adds **`ObjectKind::Thread`** and a `Thread` capability, obtained by `SPAWN_THREAD`
or by naming a thread of a domain you hold. Method `65 SET_REGISTERS` takes a memory slot
holding a full register image and installs it; `66 GET_REGISTERS` reads one out.

**Full-register, deliberately.** `kernel/src/signal.rs:196-208` records a live narrowing:
`sigreturn` restores only the caller-saved registers, because those are all the syscall stub
preserves, and callee-saved `rbx`/`rbp`/`r12`–`r15` are left to the handler's ABI to have
preserved. That is a real gap with a written excuse. A full-register primitive retires it
for free rather than carrying it into the new design.

### The reply that blocks: `BLOCK_ON`

**This is the part with a discovered constraint under it.** A hosted `futex(FUTEX_WAIT)`
must park the calling thread. The adapter cannot do that by simply not replying, because
**a server can hold exactly one outstanding reply**: `Thread::reply_to` is `Option<u32>`
(`kernel/src/sched.rs:304`), and `kernel/src/ipc.rs:24-31` states the rule as a protection
rather than a limitation — a service "cannot accumulate the ability to answer callers
later". An adapter that held a sleeper would answer nobody else.

Worse, the exploration for this RFC found that the failure is silent: `set_reply_target`
(`kernel/src/sched.rs:1522`) overwrites a live obligation with no guard, so a second `Recv`
while owing a reply strands the first caller for ever, and `abandon_caller` rescues only the
current one. **That is a defect in its own right and is recorded below.**

So the adapter always replies, and when the answer is "sleep", the reply *is* an instruction
to sleep:

```text
reply BLOCK_ON(notification, badge)
    -> the kernel blocks the calling thread on that notification
    -> the adapter signals it later; the call returns
```

Policy — which word, which waiters, what the wake count is — stays in the adapter.
Mechanism — parking a thread — stays in the kernel, which is the only thing that can do it.

**The compare-and-block race is closed for free by an existing decision.**
`notify::signal` publishes pending bits with `fetch_or` *before* waking
(`kernel/src/notify.rs:220-224`, whose comment says exactly why), so a wake that arrives
before the wait leaves the bit set and the wait returns immediately. Without that ordering
this design would have a lost-wakeup in it.

### Delivery: how a foreign call reaches the adapter

Unchanged in the nucleus: the dialect tag, and the decision to route. Changed: the
destination is an IPC send rather than a function call.

```text
hosted thread traps
  -> kernel: is this domain foreign?          (one relaxed load, as today)
  -> kernel writes the PersonalityCall into the thread's call page
  -> kernel does ipc::call on the adapter's endpoint, as the hosted thread
  -> the hosted thread blocks; the adapter serves; the adapter replies
  -> the value lands in rax
```

An IPC `Message` carries four words (`kernel/src/ipc.rs:212`) and a `PersonalityCall` needs
seven, so the frame travels in a **call page** — an RFC 0009 `Memory` object shared between
kernel and adapter, exactly the pattern `start_tcp_domain` already uses for `bin/tcpd`'s
rings.

Two details that are easy to get wrong and are therefore specified:

- **The endpoint is recorded kernel-side, not in the hosted domain's CSpace.** RFC 0031's
  interface I3 says a hosted process holds no capabilities and can name none; putting its
  adapter's endpoint in its CSpace would hand it one.
- **The delivery path retries on `Congested`.** The endpoint's queue is 16 deep
  (`kernel/src/ipc.rs:203`) and the kernel-side `ipc::call` has no retry, so an eighteenth
  concurrent hosted thread would get a spurious failure. `Congested` cannot half-happen —
  `bin/shell` documents why retrying it is safe (`user/shell/src/main.rs:245-269`) — so the
  same yield-and-retry applies.

### What the nucleus keeps, in full

The dialect tag and its bitmask; the routing decision; the six methods above; the
boundary-cost instrument RFC 0031 requires for comparing placements; `FxArea` and the
`fs_base` reload (SSE and TLS are the machine's, not Linux's). Nothing that reads a Linux
structure.

### One naming decision, taken here rather than discovered later

`domain::LINUX_DOMAINS` is a Linux *name* over a generic mechanism, and it sits on the
hottest path in the system — one relaxed load per system call, deliberately not a runqueue
lock, a choice that has already been made wrongly twice and recorded both times
(`kernel/src/syscall.rs:2494-2501`). It becomes **`FOREIGN_DOMAINS`** with the same shape and
the same single load. It does **not** become a table naming which service serves which
domain: that is a lookup on the fast path in exchange for a generality nothing needs while
there is one personality. The trigger for revisiting is written down: a second dialect.

## Step 2's record (2026-08-19): the five methods exist, and arming the gate found two tests that could not fail

`COPY_IN`, `COPY_OUT`, `MAP_AT`, `UNMAP_AT` and `PROTECT_AT` are implemented and gated.
`bin/sup` — a native supervisor that mentions Linux nowhere — starts a child, maps a page
into it that was not there, writes a word across the domain boundary, **scrubs its own copy
so the read cannot pass against a copy that did nothing**, and reads the word back out of
the child. `SET_REGISTERS` and `SPAWN_THREAD` are not built: they are not needed until
signals and `clone` move, and building an interface before its first caller is how it gets
the shape wrong.

**Three things this cost, each worth more than the code.**

**The child had to be given a lifetime.** A supervisor reaching into a child races the
child's own start — `START` parks the image and returns, and the address space is built by
the child's first thread, so `MAP_AT` straight after `START` is refused for a domain that
has not arrived yet. That refusal is correct and the fix is to wait for it. But the existing
probe modes are all wrong for this: modes 2, 3 and 4 never end, so a supervisor that started
one would hold its single child slot for the rest of the boot, and mode 6 ends *immediately*,
which makes any supervision of it a race with its own exit. Hence `bin/probe` mode 8 — yield
a bounded number of times, then exit: alive long enough to be worked on, and over without
anybody having to kill it. (A supervisor cannot kill a child it holds a handle to. RFC 0017
leaves that open, and this demonstration deliberately does not need it.)

**`MAP_AT` maps eagerly, and that is a limitation rather than a choice.** Mapped lazily, a
page has no frame until it is touched, so `translate` answers nothing and a `COPY_OUT`
straight after a legitimate `MAP_AT` is refused — which is exactly what happened. Committing
a lazy page from outside the fault handler needs the commit extracting from
`vm::handle_fault`, where it is welded to the active space and this CPU's frame reserve for
good reasons. That is step 4's work, because step 4 is when a hosted `mmap` needs laziness
for a reservation it will never touch all of. Until then a supervisor pays for what it maps,
and `MAX_SUPERVISED_PAGES` is what keeps that bounded.

**And arming the gate found two arms that could not fail.** Both are the failure mode a green
test hides, and neither would have been visible without deliberately breaking the thing each
was supposed to guard:

- The *oversized copy* refusal ran past the end of the mapping, so it was refused for being
  **unmapped** and the size bound was never reached. Raising the bound left the gate green.
  Fixed by mapping two pages, so the length is the only thing wrong with the request.
- The *not-a-domain* refusal was aimed at the console, whose object id names no live domain —
  so deleting the kind check entirely left the gate green, twice. It is aimed at
  `DomainControl` now, whose id is **zero**, and domain zero is a real domain with an address
  space: without the check, that call would map a page into somebody else's program. And it
  is asserted by its **status** rather than by "it was refused", because every one of these
  fails somehow and only the value distinguishes the handler declining the capability
  (`NoSuchMethod`) from a domain with nowhere to put it (`NoSuchCapability`). A boolean could
  not tell them apart, and did not.

## Step 3's record (2026-08-19): the personality answers from ring 3, and the boundary is priced in both placements

**`bin/linuxd` exists, and a hosted program's `getpid` is answered by a program in ring 3.**
The ratchet moved **18 → 17** — the first time it has moved, and the thing the whole
refactor is measured by.

**The delivery rule is better than this RFC originally specified, and simpler.** The design
above imagined the nucleus knowing which numbers the adapter handles. It does not need to:
the nucleus tries the handlers it still has, and **whatever none of them answers is sent to
the adapter**. So a call moving out is a deletion in `mod linux` and an addition in
`bin/linuxd`, with nothing in between that has to be kept in step — and the kernel gains no
knowledge of Linux in the process. `getpid` was deleted from `foreign_thread_call` and from
`ANSWERED` in the same change that taught `linuxd` to answer it.

**The adapter holds one endpoint and nothing else — not even a console.** That was not the
plan; it is what the boot order forced, and it is better. The adapter's first callers are the
Linux self-tests, which run long before `user_shell` starts the console service, so rather
than reorder the boot to give it somewhere to print, it holds nothing and the kernel reports
what it did from its own counters. The evidence is stronger for it: what matters is that a
hosted program got the right answer, not that the adapter said so.

**The cross-placement price, which is what RFC 0031 asked for before the move rather than
after.** One instrument, one boot, two figures:

| Placement | Floor, cycles |
|---|---|
| In the nucleus, before any call moved | **4,916** |
| Through the adapter, IPC round trip | **223,172 – 351,008** across boots |

Roughly fifty times, under emulation — and emulation is where a cycle count is least
trustworthy, which the report says rather than leaving to be assumed. **That is what the
containment costs**, and it is now a number a reviewer can argue with instead of an estimate.
The comparison is only honest because the two are priced separately: folding adapter round
trips into the nucleus figure moved it from 4,916 to 17,520 and described neither placement,
which is how the mistake was noticed.

**Four things went wrong, and three of them are worth keeping.**

**Zero is a perfectly good endpoint id.** `ADAPTER_ENDPOINT` used zero as "no adapter", and
`ipc::create` handed out id zero — so the adapter was started, its thread was blocked in
`Recv`, and every foreign call reported finding no adapter. The convention here is
`u64::MAX`, which `NET_RING_REPORT` and `NET_CONFIG` already use, and this is the reason it
is the convention.

**A report that vanishes when its instrument saturates.** The outlier cap was 20,000 cycles,
calibrated against a placement where an answered call costs a few thousand. The moment the
first call moved, every sample went past it, `priced` fell to zero, and the *entire* boundary
report — including the count of Linux numbers still in the nucleus — silently disappeared.
The cap is a million cycles now, which is comfortably above the thing being measured and
comfortably below a preemption; and the report prints whenever any foreign call happened at
all, rather than when a sample survived.

**An assertion that accepted an errno as a process id.** The personality self-test demanded
only that `getpid`'s answer be non-zero — and `-ENOSYS` is `-38`, which is not zero. So the
first boot after `getpid` left the nucleus reported that "the pid answered" while the probe
had in fact been refused. It now demands a small positive number, which is what a pid is.
**That test had been passing for a week on an assertion about nothing.**

The fourth was ordinary: `/bin` gained an entry and the listing gate said so, exactly as it
did for `bin/traced`, `bin/tcpc`, `bin/tcpd` and `bin/go-hello` before it.

**Two gates, and they fail together.** The adapter gate demands it answered a hosted program
and found no absences; the personality gate demands a pid that an `-ENOSYS` cannot satisfy.
Arming by simply not starting the adapter turned both red at once, which is the coupling
worth having: neither can be satisfied by the other.

**And step 2's supervisor gate turned out to have a bound that was wrong in a way only load
reveals.** It passed four times in isolation and failed under the full suite, and the cause
was structural rather than a matter of margin: `bin/probe` mode 8's lifetime is spent in
**its own yields**, while `bin/sup`'s progress depends on being scheduled at all. Under load
the child runs ahead and dies before the supervisor has finished working on it. Two counts in
different currencies, pulling opposite ways — the child must outlive the supervisor's dozen
calls, and the supervisor must outwait whatever is left of the child, or the reap fails and
the next spawn is refused for the budget. The margin now sits on the side that can lose it,
sixteen to one. **Widening a timeout would have hidden this; the fix is that the two bounds
are now written down as the pair they are.**

## Step 4's record (2026-08-19): three of the four memory calls move, and the prediction about what they would need was wrong

`munmap`, `mprotect` and `madvise` are answered by `bin/linuxd`. The ratchet moved **17 → 14**.
A hosted program maps two anonymous pages, writes and reads the second, unmaps them and has
its `madvise` taken as advice — exactly as before, and it cannot tell that three of those
calls are now serviced by a program in ring 3 through a capability invocation.

**The prediction this RFC made about step 4 was wrong, and pleasantly.** It said the memory
calls would need RFC 0009's unbuilt `Memory` creation method, "because a hosted `mmap` must
make an object at runtime". They do not: `MAP_AT` maps *anonymous* pages into a domain, which
is what an anonymous `mmap` is, so no object is created at all. The creation method is still
unbuilt and is still owed — a hosted `mmap` of a *file* will need it — but it is not what was
blocking this step, and saying so is cheaper than letting a wrong prediction stand.

**What did block it was authority, and the shape of the fix is the design working.** The
adapter cannot touch a hosted process's memory without a `Domain` capability for it, and it
has no way to make one. So the kernel grants it: a capability per hosted domain, at CSpace
slot `32 + id`, which the adapter computes from the badge — no table to keep in step. It is
keyed by the domain's **generation**, not by "have we done this", because a domain slot is
reused and handing the adapter a stale handle would leave the *next* domain 3 refused for a
reason that has nothing to do with what it asked. This kernel learned that lesson once
already, on the same day, when a thread outliving its domain decremented a counter the next
occupant owned.

That grant is a stand-in and is written down as one: RFC 0031's interface **I5** wants the
adapter to create hosted domains itself, at which point it holds the capability by
construction and the kernel does not grant anything. Until something other than a self-test
makes a Linux domain, this is the honest arrangement.

**`mmap` stays in the nucleus, and the reason is a sentence rather than a shrug.** It takes
six arguments; an IPC message carries four. Moving it needs a page shared between kernel and
adapter rather than a message — which is also what signal delivery needs, so it is one piece
of work rather than two, and it is step 5's first piece.

Armed by making the adapter stop answering `munmap`: the memory self-test went red with
`munmap -38`, which is the proof that these calls really are being serviced in ring 3 and not
merely appearing to be.

**And the adapter gate failed once under the full suite, which found a counter measuring three
things at once.** It reported "1 found no adapter to ask" — a sentence that could mean an
adapter that was not there, an endpoint that refused the message, or a caller that gave up
retrying against a queue that stayed full. Those want a boot-order fix, a dead-adapter fix and
nothing at all, respectively, and one number could not tell them apart. They are three
counters now, all three printed, and the gate quotes the line it saw when it fails — because
under a full suite the serial log is a temporary file that is already gone by the time anyone
reads the failure.

**What is honestly known:** the suite is green, and a deliberate three-way concurrent
reproduction produced zeros in all three counters. **What is not known** is which of the three
the original failure was, because it happened before they were separated. The next occurrence
will say. That is the whole of the claim, and it is smaller than "fixed".

## Step 5's record (2026-08-20): `mmap` moves, and moving it found two things nothing else could

`mmap` is answered by `bin/linuxd`. The ratchet moved **14 → 13**, and the memory family is
complete: every one of `mmap`, `munmap`, `mprotect` and `madvise` is now decided by a program
in ring 3 and performed through a capability it holds.

**It did not need the shared page this RFC predicted, and the reason is worth stating.** Linux
passes `mmap` six arguments and an IPC message carries four. The two that do not fit — `fd`
and `offset` — matter only for a *file* mapping, which this personality refuses whole. So the
adapter passes `fd = -1` and refuses anything without `MAP_ANONYMOUS`, which reaches the same
answer for every request either could have refused. **One behaviour changes and it moves
toward Linux**: the nucleus also refused an anonymous mapping carrying a non-negative fd,
which Linux ignores. File mappings will need all six and therefore the page; that cost is now
a written expectation rather than a surprise.

**`MAP_AT` gained two flags, and each is a Linux semantic made explicit rather than assumed.**
*Lazy* — record the region, take no frame until a page is touched — because a runtime reserves
address space by the gigabyte and touches a little of it, and an eager mapping would refuse a
program on a machine with ample memory. *Replace* — Linux's `MAP_FIXED`, whose specification
is precisely "the overlapping part will be discarded" — opt-in, so the default stays the
refusal this RFC argued for, and whole-regions-only, so a partial overlap is refused where it
can be seen rather than approximated.

### What the move found

**Moving `mmap` changed what the Go corpus does, and no amount of reading the diff said why.**
212 calls became 401 and the complaint changed from "cannot allocate memory" to "out of
memory". So the adapter was given a report page — it holds no console — and made to trace what
it is asked. The trace answered in one boot what two rounds of reasoning had not:

```text
#2 addr 0xc000000000 len 0x4000000 pages 16384 prot 0 hinted
#3 addr 0xc000000000 len 0x4000000 pages 16384 prot 2 fixed
```

**Reserve, then commit.** The runtime reserves a 64 MiB arena `PROT_NONE`, then maps *the same
range* read-write over the top with `MAP_FIXED`. The second was refused, because `MAP_AT`
would not overlap an existing region — and that refusal was the "out of memory". With the
replace flag it succeeds, and the runtime goes on to map four more arenas.

**Then it faults, and the fault is a kernel limitation this project has never been able to
reach before.** Writing to the arena it has just mapped, the fault handler answers *"the fault
was legal but could not be serviced: could not map the demanded page"* — `paging::map_page`
could not get page-table frames from the per-CPU reserve, because `0xc000000000` is the first
address anything on this machine has ever touched in a fresh PML4 slot and it needs three new
table levels at once. The reserve exists precisely so the fault path never waits on the
allocator's lock, and it is sized for a page rather than for a page plus its tables.

**That defect is fixed, and the fix was written down before it was needed.** `frames.rs`'s own
caveat said: *"It does not survive a burst. `RESERVE_FRAMES` faults on one CPU between refills
is the budget… Sizing it against a real fault rate needs a workload."* The workload arrived.
Sixteen became sixty-four, faults missed went from one to **zero**, and the arena is served.

**And then the corpus reached something no version of it ever has.** It faults on an
instruction fetch at `0xffffffffff600000` — the **Linux vsyscall page**. This RFC's parent
states the opposite as a design assumption: *"No vDSO. Omitting `AT_SYSINFO_EHDR` makes Go
fall back to real system calls for `clock_gettime`."* **For this Go it does not**: it falls
back to the legacy vsyscall page, a fixed kernel-half address that must be mapped and
executable. RFC 0005's assumption is corrected in place, and the requirement is now named
rather than guessed at.

The number that says how much this changed: the corpus reaches the clock in **10 system calls**
where it previously thrashed through 212 and then 401. Memory is no longer what stops it.

**One behaviour of the machine changed with it, and it is a principle rather than an
expedient.** A hosted foreign program faulting with no handler installed used to print the
full exception report — which claims the machine went wrong, trips every blanket "no
EXCEPTION" check in the suite, and is untrue: the containment worked, and the kernel's own
next line says the domain is gone and the machine is still running. RFC 0005 step 4 already
makes half this argument three lines earlier — *a delivered signal is not an exception the
machine needs to narrate* — and the other half follows from the same reasoning. It is now one
line carrying the address, the instruction, **and why no signal was delivered**, because a
hosted program *entitled* to survive a fault that did not is a personality bug rather than a
program bug, and nothing else can tell the two apart.

**The corpus is a witness, not a gate**, which is why none of this turned the suite red: what
the boot demands is that the histogram be printed, and the histogram is the deliverable.

## Step 6's record (2026-08-20): a hosted program's fault crosses to ring 3

**A fault now reaches the personality.** The kernel writes the faulting
register file into a slot of a page it shares with `bin/linuxd`, calls the
adapter through the same door a system call goes through, and the adapter
answers *resume* — having edited the registers — or *end this program*. Two
more calls moved with it (`rt_sigprocmask`, `sched_getaffinity`), taking the
ratchet **13 → 11**.

**Two facts had to be established before any of it could be attempted, and
neither came from reasoning about the design.** The first exploration for
RFC 0032 concluded flatly that *"the fault path cannot IPC"*. That was half
right and the half it got wrong is what made this step possible:

- The IDT uses **interrupt gates**, so a fault arrives with `IF` clear. A
  thread that blocks with the mask up leaves its CPU deaf to the tick, the
  wake and the shootdown that would resume it — the exact hazard that once
  hung this kernel. So interrupts are enabled first, with the same argument
  the syscall entry already makes for doing it there, and the same
  precondition: a user-mode fault holds no kernel lock.
- The page fault is **deliberately not on an IST**, and `idt.rs` says why:
  *"IST stacks do not nest — a second page fault while handling the first
  would overwrite the first one's frame."* It runs on the faulting thread's
  own kernel stack. **That is what makes blocking sound at all** — the frame
  belongs to the thread, so being switched away preserves it exactly as a
  blocked system call's is preserved.

Both were read out of the code that states them. Neither is in the earlier
exploration's answer.

**What the adapter may do to a resuming program is bounded by the kernel, not
by the adapter's good behaviour.** It gets fifteen general registers, `rip`
and `rsp` — which is what a signal handler is — and cannot set `cs`, `ss` or
the error code, because an adapter that could write those could resume a
hosted program in ring 0. `rflags` is masked to the arithmetic and direction
bits: not `IF`, so it cannot disable interrupts; not `IOPL`, so it cannot
reach the ports.

**One slot per fault in flight, claimed atomically**, because two CPUs can
fault at once and a single buffer would hand one of them the other's
registers. A fault that finds no slot ends the program rather than waiting,
because a thread waiting for a slot while holding nothing is a hang with no
diagnosis.

### What this step did not do, and why that is the honest boundary

The adapter answers **END** to every fault, and that is correct rather than
unfinished: while `rt_sigaction` is still in the nucleus, the adapter does not
own the signal dispositions, so it cannot know whether a program had a
handler. The kernel's own delivery runs first, so the only faults the adapter
sees are the ones nothing wanted — exactly the set that should end. When the
dispositions move, that arm grows a decision and the kernel's delivery goes
away. **`0 resumed` is the right answer today, and the gate demands the
crossing rather than the resume for that reason.**

### Two instruments caught their keeper

**The boundary report's own arithmetic.** Faults travel through the same call
as system calls, so they were counted as answered calls — and the accounting
line said *"SOME UNCOUNTED: 37 of 36"* before any human noticed. It was built
to catch exactly this, and it did, in the first boot after the mistake.

**And the new gate could not fail, until it was armed.** Its first version
asked only whether the crossing had been reported; disabling the crossing
entirely made it fall into the "nothing faulted" branch and pass. That is the
**third** gate in this suite with that shape and the third found by
deliberately breaking what it guards. It now keys on the hosted program's own
fault line — which prints whatever happens next — so "a program faulted and
the personality never saw it" is a failure rather than a silence.

**And a third instrument found a fourth thing sharing one counter.** The suite
reported *"1 were refused by its endpoint"* — and because the gate had been
made to quote the line it saw, the diagnosis was in the failure rather than a
rebuild away. A hosted thread whose domain is being killed is woken out of its
wait with `Abandoned`, which reaches the caller as `NoSuchEndpoint`: the same
value a genuinely missing endpoint gives. **A caller being killed is teardown
working, not an adapter failing**, and the thread's own dying flag is what
separates them. That is now a counter of its own, and the gate ignores it.

Counting the ones already split out, this is the fourth time in two days that
a single number has been found standing for several different conditions. The
pattern is worth naming: *a counter whose name is a sentence about intent
rather than about a distinguishable event will eventually be measured by
someone who needs the distinction.*

> **Every kernel `unsafe` figure in this document was taken with a scanner that
> over-counted, and they are left as they were rather than rewritten.**
> `tools/check-unsafe-budget.py` took a whole line's brace balance, so a line
> that both closed an `unsafe` block and opened another read as still-open and
> charged the outer block's body to the crate. Measured at this document's own
> tree (`9c893b3`, 2026-08-20) after the fix of 2026-08-24: **1,510 by the old
> scanner, 1,368 by the corrected one — an over-count of 142.** The *deltas*
> below are still sound, because every number in a delta was taken the same
> way; the absolutes were about ten percent high. Today's figures are on the
> corrected scale, so the kernel's real growth since this RFC is 1,368 → 1,759
> and not the 1,506 → 2,167 a naive comparison would show.

**The kernel's `unsafe` budget went down while this was added**: 1,514 to
1,512. The memory calls left with their `uaccess` copies, and handing a fault
to ring 3 needs one `unsafe` line — the `enable_interrupts` above. A
personality leaving the kernel takes its pointer arithmetic with it, which is
this whole RFC's argument stated as a number.

## Step 7's record (2026-08-20): the personality decides what a fault means, and the kernel stops knowing

**A hosted program's `SIGSEGV` is now delivered by a program in ring 3.** It faults; the kernel
hands the register file to `bin/linuxd`; the adapter finds the handler *in its own table*,
builds the `ucontext`, writes it onto the faulting process's stack through a capability, edits
the registers in the slot, and answers *resume*. The handler runs, reads `cr2` out of the
`ucontext`, edits the saved `rip`, and `rt_sigreturn` puts it back. The ratchet reads **9**.

**What the kernel no longer knows.** Which signals a domain has handlers for. What a
`struct sigaction` looks like. Where an alternate stack is. What a `ucontext` contains, or
that a handler takes three arguments. `kernel/src/signal.rs` was 238 lines and is now the
`rt_sigreturn` half alone.

**What it kept, and the boundary is worth stating precisely.** It puts registers back — and
refuses `cs`, `ss` and `IF` whatever the adapter writes, so a personality bug cannot resume a
hosted program in ring 0 or with interrupts off. It performs copies between an object and a
domain, on a capability the caller holds. It knows a fault happened and to whom. Nothing in
that list is Linux-shaped, which is the test RFC 0031's interface I1 sets.

### The hazard that had to be handled with it

**Domain ids are reused, and the adapter now keeps state keyed by them.** A new domain 3
inheriting the old domain 3's handlers would let a program that never installed one *survive a
fault it should have died on* — which is worse than a crash, because it is a crash that did
not happen. So the kernel tells the adapter when a slot is reused, on the same endpoint, under
a method no Linux number can be. It is sent **only when a previous incarnation was
remembered**, so a fresh domain's first foreign call does not pay for a round trip that has
nothing to forget.

This is the third time this kernel has met that hazard in two days: a thread outliving its
domain decremented its successor's counter; the adapter was handed a stale `Domain`
capability; and now this. **Reused identifiers are this design's recurring sharp edge**, and
each occurrence has been found by a different route — a flake, a refusal, and reasoning about
what moving state means.

### `rt_sigreturn` stays in the nucleus, with a reason rather than a shrug

It needs the interrupted stack pointer to find the frame, and a message carries four words
that are already the call's own arguments. Giving *every* foreign call a register frame would
make the hot path pay for one call. The honest fix is a per-call slot when something else
needs one; until then the kernel restores registers using the layout
`bhaskix_personality::signal` has always owned, which is the same code the adapter builds them
with — so the two cannot drift.

Its documented narrowing survives the move unchanged, and is now known to be **structural**:
`SyscallFrame` holds only the caller-saved registers, because the entry stub only saves those.
A handler that edits `rbx` in the `ucontext` and expects the edit to take would need the stub
widened, not the personality moved.

**Armed:** making the adapter decline to find a handler turned the signal round trip red —
`resumed 0, returned 0` — which is the proof that the delivery is the adapter's and not a
kernel path still running underneath.

**The kernel's `unsafe` budget fell again**, 1,512 to 1,507. Two steps, two reductions, while
the machine gained a fault upcall and a personality that decides what a signal means.

## Step 8's record (2026-08-20): `clone` and `rt_sigreturn` move, and the four-word wall comes down

**Both of the calls that could not fit in a message now live in ring 3.** `clone` takes five
arguments; `rt_sigreturn` takes none but needs the interrupted stack pointer. A message
carries four words. The ratchet reads **7**.

**The answer keeps the nucleus ignorant, which is the whole test.** The kernel does *not* know
which calls need more than four arguments — teaching it would be Linux knowledge arriving by
the back door. Instead the adapter answers **"ask me again with the register frame"**, the
kernel stages the caller's frame in a slot of the page it already shares for faults, and asks
again under a method no Linux number can be. Only the calls that need it pay for it, and the
list of which those are lives entirely in ring 3.

The same mechanism gave `rt_sigreturn` its answer shape: its reply is not a number but a
**register image**, so the kernel resumes the caller from the slot rather than writing `rax`.
That was always what `rt_sigreturn` did; it is now said through the boundary instead of inside
it.

**The staged frame has holes, and they are the truth.** A system call arrives through the
`SYSCALL` stub, which saves the caller-saved set and nothing else, so `rbx`, `rbp` and
`r12`–`r15` read as zero. Every Linux call needing a fifth or sixth argument takes it in
`r10`, `r8` or `r9`, which *are* saved. A call wanting a callee-saved register is one this
cannot serve, and the zero says so rather than inventing a value.

**`SPAWN_THREAD` is the sixth supervisor method**, and it carries none of `clone`'s meaning: an
entry, a stack, one word in `rdi`. Which flags made the request legal, what a thread group is,
and what the caller gets back are all decided in ring 3. This personality's own contract —
that the child starts at the address in the *sixth* argument slot rather than resuming after
the `syscall` as Linux does — moved across unchanged and still says so, because moving code is
not the moment to quietly change what it promises.

**`kernel/src/signal.rs` is gone.** It was 238 lines two steps ago; its last resident,
`rt_sigreturn`, left with this one. The lock rank it held is still there because the futex
queues still use it, and its documentation now names what actually lives at that rank rather
than what used to.

**The accounting instrument caught the same class of mistake for the second time in two
steps**: the retry is the second half of a call already counted, and counting it again made the
report say *"SOME UNCOUNTED"* on the first boot after the mechanism existed. Faults, retries
and forget-messages are all deliveries that are not system calls, and all three are excluded
by name now.

**Armed** by having the adapter spawn a thread at entry zero: the clone self-test went red with
`parent saw -11`, which is the refusal travelling all the way back from `SPAWN_THREAD` to a
hosted program's `errno`.

**The kernel's `unsafe` budget fell a third time**, 1,507 → 1,504 — the last `uaccess` read the
personality had in the nucleus went with `rt_sigreturn`. Three consecutive steps, three
reductions, while the machine gained a supervisor interface, a fault upcall, a register-frame
exchange and a personality that decides what a signal means.

### What is left, and what each one needs

Seven numbers: `futex`, `gettid`, `exit`, `exit_group`, `sched_yield`, `write`, `arch_prctl`.
None is a parser and none reads a hosted structure, which is why the interesting half of this
refactor is finished even though the count is not zero.

- **`futex`** needs `BLOCK_ON` — and that needs the adapter to *hold notifications*, which it
  cannot create. Boot can grant it a pool, and the adapter's single thread makes the
  compare-and-queue atomic against other futex operations for free. The lost wakeup that shape
  would normally have is already closed by `notify::signal` publishing its pending bits before
  waking.
- **`gettid`** needs the thread's identity, which the badge could carry beside the domain.
- **`exit` and `exit_group`** need a way to end a thread or a domain from a capability, which
  RFC 0017 deliberately left open.
- **`sched_yield`** must yield the *caller's* thread, which only the kernel can do.
- **`write`** needs the adapter to hold a console, which it cannot be given before the console
  service exists.
- **`arch_prctl`** sets a thread's TLS base — a seventh supervisor method, and a generic one.

## Step 9's record (2026-08-20): five more numbers leave, and the ratchet reads two

**`gettid`, `arch_prctl`, `sched_yield`, `exit` and `exit_group` are answered in ring 3.** The
ratchet reads **2** — `futex` and `write`, and each is two because a capability that does not
exist yet, not because the boundary was drawn there on purpose.

**Three of the five are not questions at all, they are acts on the caller** — give up a slice,
end this thread, end this thread group — and only the kernel can perform them. The shape that
carries them is the one step 6 already built: the reply says *what to do* rather than
returning a value. Three new reply words, `YIELD`, `END_THREAD` and `END_DOMAIN`, and the
nucleus still does not know which Linux number meant which. That distinction is the whole
design in one line: `exit_group` ending a *domain* is a decision made in ring 3 by the dialect
that knows what a thread group is.

**`gettid` needed the badge to say more, and a badge is the one identifier a caller cannot
forge.** Its low half was already the hosted domain; its high half is now the calling thread,
stamped by the kernel from the capability actually used. The tid a hosted program sees is that
number, offset by one so no thread is ever tid zero — the same offset `clone` already returned
and the same one the nucleus used before the move, so a hosted program cannot tell that
anything changed. Naming the thread *back* to the nucleus undoes the offset, in one place.

**`SET_TLS` is the seventh supervisor method, and it is where this step found a real bug.**
`sched::set_fs_base` wrote `IA32_FS_BASE` unconditionally — correct for every caller it had,
because the only caller was a thread setting its own. A supervisor setting *another* thread's
base made that wrong: the write landed on whatever thread was on the supervisor's CPU. It now
loads the register only for the thread that is running here, and the switch loads the arriving
thread's base **even when it is zero**, because the old `!= 0` test let a thread with no TLS
inherit its predecessor's — another domain's pointer sitting in this thread's segment base.
The first half is gated; the second is reasoned, and what would show it is a thread with no
TLS reading `fs:` after one that had some, which nothing in this system does yet.

### Four gates that could not fail, and now can

- **`exit` never returns** was read out of a slot that a fresh page had already zeroed. An
  `exit` that came back answering zero looked identical to one that never came back. The probe
  seeds the slot with `0xe217` before the call now, so the value survives only if the store
  after it never ran — and with the seed in place, an adapter that answered `exit` as a value
  turned the gate red.
- **`exit_group` had no gate at all.** No probe called 231; the Go corpus does, and the corpus
  is not gated. The clone probe's parent now waits for a word the test writes *after* reading
  its numbers — the domain's report frame is what those numbers live in — and then calls
  `exit_group` while the child is still spinning. What is counted is the **child**: the thread
  that asked for nothing. Armed by answering `exit_group` as `END_THREAD`, which left the child
  running and the gate red.
- **`arch_prctl` had no gate either.** The thread probe now sets its base to a witness word in
  its own report page and reads it back through `fs:[0]`. The read is what makes the answer
  mean anything: a call that wrote the register on the wrong CPU also answers zero. And the
  base is set by a *different thread*, in ring 3, while the caller is blocked in the
  rendezvous — so a base that did not travel with the thread through the switch back could not
  produce this value.
- **A supervisor setting a thread it does not own** is refused, and `bin/sup` asks for thread
  1 — a live thread in domain zero — rather than an id that does not exist. An id that does
  not exist is refused by the scheduler's own lookup and says nothing about ownership. With the
  ownership check deleted, that call succeeded and the gate went red.

### The instrument stopped reporting a mean over nothing

With the calls gone, the in-nucleus placement has **no sample to price**: `futex` blocks by
construction and is excluded, and `write` may never be called. The boundary report printed
`floor 0 cycles over 0 non-blocking calls, mean 0`, and the both-placements line printed
`nucleus floor 0` — a confident zero standing for "nothing was measured", which is the exact
confusion this instrument exists to prevent and which its own gate's comment warns about. Both
say so in words now. The cross-placement comparison stands on the figure recorded in step 3's
table, taken while there was still something in the nucleus to compare against.

### What is left

**`futex`** still needs `BLOCK_ON` and a notification pool the adapter cannot create, and
**`write`** still needs a `Console` the adapter cannot be given before the console service
exists. Both are capabilities, not code — which is why the ratchet reads two rather than
zero, and why the remaining work is a grant rather than a translation.

The kernel's `unsafe` budget **rose** for the first time in four steps, 1,504 → 1,507, and all
three lines are instrument: two `read_volatile`s for the TLS witness and one `write_volatile`
telling the clone probe it may end its group. The five calls that moved took no `unsafe` with
them, which is why they were the ones left.

## Step 10's record (2026-08-20): the ratchet reads zero, and `mod linux` is empty

**`futex` and `write` are answered in ring 3, and the nucleus interprets no Linux number at
all.** The boundary count that read **18** on 2026-08-19 reads **0**. Its gate is no longer a
ratchet that may fall but an equality that may not move: a number here again is a Linux
concept back in the nucleus, caught on the next boot rather than in review.

**Both of the last two wanted a capability rather than code, exactly as step 8 predicted.**

- **`write` needed a console.** The adapter is granted one at boot — `Rights::WRITE` and
  nothing else, so it may put a character and may **not** take a byte somebody typed at the
  shell. That narrowing was a comment until this step: the console path checked no rights,
  because the console service was its only holder and held `Rights::ALL`, so a check would
  have been unreachable code. It is a mechanism now, and arming it — granting `READ` instead
  — turned the write gate red.
- **`futex` needed a way to park a thread**, which is `BLOCK_ON`: the adapter always replies,
  and when the answer is "sleep" the reply *is* the instruction to sleep. Sixteen
  notifications are granted at boot, one per parked waiter, so `futex(WAKE, n)` is exact —
  waking *n* means signalling *n* of them, where a notification shared by every sleeper on one
  word could only wake all or none. The pool is also the limit: a seventeenth sleeper is
  refused with `EAGAIN` rather than lost.

**The compare-and-park is atomic without a lock, and the reason is structural.** The adapter
has one thread and answers one request at a time, so nothing can change a futex word between
the compare and the reply that parks on it. The remaining window — between the reply and the
kernel's park — is closed by a decision made long before this RFC: `notify::signal` publishes
its bits *before* waking, so a wake arriving in the gap leaves the bit set and the park
returns at once. Neither half is new work; both are why this shape was chosen.

**The instrument lost a boundary violation nobody had counted.** `blocks_by_construction` was
a `match` on Linux syscall numbers in the nucleus, deciding which calls not to price. The
ratchet never saw it, because the ratchet counts numbers that are *answered* and this one only
decided *pricing* — a Linux list hiding behind an instrument. It went with the last number,
and the calls that block are still excluded from the adapter's figure, but by where the round
trip ends rather than by the kernel knowing what `futex` means.

### What a hosted program's `write` costs now, and the property that changed with it

A `Console` capability confers the authority to put **one character**. Sixteen bytes is
sixteen invocations, and a write is therefore no longer atomic against other output: where the
line begins depends on what the console was in the middle of. That is a real property of a
console that is a capability rather than a kernel function the personality may call, and it is
recorded here rather than hidden behind a stricter test pattern. The boot gate matches the
string without anchoring it, and says why.

### Four gates, and one path that has none

`write` is gated in both halves — the count the adapter answered *and* the string appearing on
the console, because a count with no string would pass on an adapter that answered and printed
nothing. `futex` is gated by the rendezvous that already existed: a parent that sleeps, a
child that wakes it, and `woke 1` demanded rather than relaxed. Each new path was watched red
by a deliberate edit: the adapter answering `EAGAIN` instead of parking, the compare skipped
so a stale word sleeps, `BLOCK_ON` naming a capability that is not a notification, and the
wake signalling nothing.

**The pool-exhaustion path is not gated**: nothing in this system starts seventeen hosted
threads that sleep at once, and a test that did would be a test of the test. It is stated so
that the next reader knows it is untested rather than assuming the count of armed gates
covers it.

### A hosted thread parked in a futex could not die, and the gate that watched it was blind

**The last call to move brought the kernel a case it did not have.** A thread parked in
`notify::wait` is an ordinary waiter — but `block_unless` refuses to mark a *dying* thread
blocked, because sleeping is the one thing a thread told to stop must not do. So a hosted
thread parked on a futex whose domain ended underneath it — a sibling calling `exit_group`,
which is now an ordinary event — kept deciding to block, was refused, and spun through the
scheduler for ever: a thread that could not die because it was waiting for something nobody
would send. `notify::wait` checks `sched::should_die()` now and returns `Gone`, which is what
every other blocking path in this kernel already does at its own safe point.

**And the test that was meant to prove this passed while the bug was in.** It asked
`threads_in_domain`, which treats a runqueue it could not lock as empty — and the failure it
was looking for is a thread *spinning*, which keeps exactly that lock busy. The gate passed
because the bug was bad enough to hide itself. It asks `threads_counted_in` now: an atomic
maintained at create and exit, which nothing a thread does can make lie. Armed with the fix
removed, it reads `parked true, group ended false`, which is the sentence the machine should
say.

The probe was rebuilt to prove the pair in one shot: the parent parks in a futex on a word
nobody will ever change, and the **child** — a thread that asked for nothing — calls
`exit_group`. What the test waits for before ending the group is not a sleep but two witnesses
that cannot both be wrong: the parent's own word, written from ring 3 immediately before the
call, and the kernel's count of threads parked by a `BLOCK_ON` reply.

**A third mistake, and it is an old one in a new place**: `mov qword [r15+128], 1` assembles a
`disp8`, which is *signed* — the announcement landed a hundred and twenty-eight bytes below
the report page. The symptom was `parked false` with every other number right, which is what
sent the search to the encoding rather than to the design.

### A finding the manifest could not express

`packages/linuxd.manifest.in` is meant to be the reviewable list of what this domain may do —
RFC 0030's whole claim about packages. It cannot describe this domain. The grammar has no way
to say **write-only** about a console, and no way to say **sixteen** notifications:
`MAX_CAPS` is sixteen *distinct authorities*, and sixteen identical notifications are one
authority with a multiplicity, which the memory line already has a spelling for (`pages=`).
Twelve `cap notification` lines would fit and would be a *wrong* list, so the manifest
describes them in prose and lists what it can. The trigger for `cap notification count=N` and
`cap console write` is written down there: the first package that is **installed** rather than
started by the kernel and needs either. Nothing is granted from that file today —
`start_linux_domain` makes these grants at boot.

### One event seen once, and not explained away

A full-suite run printed `LOCK ORDER blocking on wait::WaitQueue (rank 9) while holding mask
0b1000000000, at kernel/src/wait.rs:195` in the dark `qemu64` lane; two isolated runs of that
lane and a second full suite were clean. `sync.rs`'s `Drop` documents **this exact sentence**
as a false positive it fixed once — a rank bit cleared an instant late makes the next
acquisition of the same rank look like two at once — and the only `WaitQueue`s left are two
kernel self-tests, because this step deleted the sixteen futex queues. Recorded as *observed
once, not reproduced*, which is smaller than "unrelated".

### What this closes

- The kernel's `unsafe` budget falls to **1,506**, and the line that went is the one that
  mattered: `futex_word`'s `uaccess` read, the last time the nucleus dereferenced a pointer on
  a Linux call's behalf.
- `kernel/src/syscall.rs` has **no `if` between a foreign call arriving and the adapter being
  asked**. Interface I1 is written as the absence of code rather than as a paragraph.
- The lock rank that was `signal::DISPOSITIONS`, then `syscall::FUTEX_KEYS`, now holds
  nothing. The variant stays, because rank numbers are an *order* and renumbering would
  rewrite the meaning of every recorded violation.
- `security.md` §1's **T11** mitigation column becomes true. A bug in the Linux translator is
  now a bug in a ring 3 program holding one endpoint, three pages, a write-only console,
  sixteen notifications, and a handle to each domain it hosts.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Leave the personality in the nucleus** | T11 stays unmitigated; Tier 2 is unbuildable (RFC 0005 step 9); the ratchet stays at 18 for ever | Never — the RFC that requires the move is accepted and its reasoning has only strengthened |
| **The hosted process runs adapter code itself** (a vDSO-style upcall into the adapter mapped in the process) | No cross-domain authority needed, but the adapter then runs *in the hosted domain*, sharing its CSpace — so it cannot hold the directory or socket capability the process must not be able to name, which is the entire point | Hardware protection domains within an address space (PKS/MPK), which this project does not use and would have to justify separately |
| **A deferred-reply mechanism** (a server may hold several callers and answer out of order) | It is refused *by design*, and the design is right: `ipc.rs:24-31` — a service "cannot accumulate the ability to answer callers later". Adding it to serve a futex would weaken IPC everywhere to fix one call | A workload appears whose blocking calls cannot be expressed as `BLOCK_ON`; none is known |
| **Reply `LATER` and be polled**, as `bin/tcpd` does for `accept` | Correct for `accept`, wrong for a futex: a Go scheduler parking on a contended mutex would spin instead of sleeping, which is precisely the "deadlocks under load rather than failing visibly" failure RFC 0005 warns about | The blocking call is rare and coarse, as `accept` is |
| **Give the adapter the hosted domain's page-table root** and let it map directly | It is not a capability, it is a number that confers everything; and a supervisor that could write page tables could map any physical frame | Never |
| **A general "copy between two addresses" syscall** | The kernel would have to validate two addresses in two spaces, and the supervisor names memory it may not own. Naming a `Memory` object it holds makes the authority the argument | Never — this is `DRAIN`/`FILL`'s settled shape |

## Impact on existing design documents

| Document | What changes |
|---|---|
| [architecture.md](../architecture.md) | §3's capability table gains `Thread`; §4's personality section gains the delivery picture; §8's **A6** is answered in part — *where* the personality runs is settled by this RFC, *what a hosted process is* stays open |
| [security.md](../security.md) | §1 **T11**'s mitigation becomes true when the move completes, not when this RFC is accepted, and the note must keep saying so until then. §6 gains a row: a supervisor's reach into a domain it holds |
| [RFC 0009](0009-shared-memory.md) | Its unbuilt `Memory` creation method is needed by step 4 and is called out here rather than rediscovered |
| [RFC 0031](0031-linux-compatibility-as-an-adapter.md) | §5's relocation gets its mechanism; the trigger stands |
| [RFC 0005](0005-linux-abi-compatibility.md) | Its "Where it lives" correction gets a date it can actually happen on |

## Security implications

Reference [security.md](../security.md) §1.

- **New authority: yes, and this is the RFC's substance.** A `Domain` capability with `WRITE`
  becomes materially more powerful. The mitigations are that it is held rather than ambient,
  scoped to domains the holder made, transitively revocable, and one-directional.
- **Reachable without a capability:** nothing new. Every method refuses without the
  capability and the right.
- **New parser for untrusted input:** no. These take scalars and a `Memory` slot. The
  parsers are what *leaves* the kernel.
- **Scope movement:** T11 moves from "in scope, not mitigated" toward mitigated — but only
  when the personality actually moves, which is steps 3–7, not this document.
- **A new failure mode, stated:** a compromised supervisor now compromises the domains it
  holds. That is strictly better than today, where the same code compromises the kernel.

**Two existing defects surfaced while writing this, recorded because they are real:**

1. `sched::set_reply_target` (`kernel/src/sched.rs:1522`) overwrites a live reply obligation
   with no guard. A server that receives twice without replying strands its first caller for
   ever, silently, and `abandon_caller` rescues only the current one. `Recv` should refuse,
   or abandon the displaced caller with `Revoked`.
2. `kernel/src/ipc.rs:817-818` says a thread blocked in `call` "cancels itself on the way
   out". It does not — `ipc::call` has no `cancel` on its error exits. Sound today because
   `cancel_all` at exit covers it, but the comment is stale and a future change could rely
   on it.

Neither is caused by this RFC and neither blocks it. Both are the kind of thing that goes in
the record rather than in a corner.

## Performance implications

The dispatch fast path is the only place this can regress: one relaxed load per system call
today, and it must stay one. `FOREIGN_DOMAINS` keeps the shape.

The measurable change is the foreign-call price, and the instrument for it already exists
and already has a number: **4,916 cycles** floor per non-blocking foreign call in the
nucleus placement (RFC 0031, step 10). The domain placement is measured by the same
instrument, on the same boot line, and **the difference is what the containment costs.**
That comparison is the deliverable of the first slice, not an afterthought — RFC 0031's
performance section requires the number before the move rather than after, and half of it is
already in hand.

## Testing plan

- **Host:** argument decoding for the six methods, as pure functions over scalars, in the
  same shape `personality/` uses.
- **QEMU:** the interface is proven by a **native** supervisor — `bin/sup` maps a page into
  its child, writes through `COPY_OUT`, reads it back with `COPY_IN`, and asserts the child
  saw it. Proving it with Linux would prove only that Linux plumbing works; proving it with
  `bin/sup` is what shows the methods are generic. Refusal arms: no `WRITE` right, a domain
  the caller does not hold, an address outside the target's mappings, a length that
  overflows its object.
- **Negative-armed**, every gate, by a string-flip edit before it is believed.
- **Real hardware:** nothing here needs it.
- **Fuzz:** no new parser, so no new target. The argument decoding is scalars.

## Unresolved questions

1. **Does a `Thread` capability need a generation?** A thread id can be reused; a capability
   naming a dead thread must not reach its replacement. The `Domain` table solved this with
   generations and the fix is probably the same, but it is not written yet.
2. **What happens to a hosted process when its adapter dies?** Proposed: the workload ends —
   blocked callers already get `Revoked` via `abandon_caller`. Stated so it is a decision
   rather than a consequence.
3. **How many adapter threads serve one endpoint?** One reply obligation per thread means
   concurrency is thread count; the receive queue holds 16. Decided by the first workload
   that has more than a handful of hosted threads.
4. **Should `SET_REGISTERS` be allowed on a *running* thread**, or only one stopped at a
   trap? Only-stopped is safer and is all signals need. Deferred to whoever writes a
   debugger.
5. **RFC 0009's `Memory` creation method** — needed by step 4 for a hosted `mmap`. Its own
   small RFC amendment, not this one.

## Implementation plan

1. **This document**, plus the corrections it names in `architecture.md`, `security.md`,
   RFC 0031 and the tracker.
2. **The methods in the kernel**, over `vm::with_space` (new, beside `with_active`) and the
   `translate` + direct-map idiom `elf::load_into` already uses for a space that is not
   installed. Proven by `bin/sup`, negative-armed. ✅ *Delivered 2026-08-19 — see the record
   below.*
3. **`bin/linuxd`, and `getpid` end to end** — the whole path, one call, everything else
   unchanged. The ratchet moves **18 → 17**, the first time it has moved. ✅ *Delivered
   2026-08-19 — see the record below.*
4. **The memory calls.** ✅ *Delivered 2026-08-19, three of the four — see the record below.*
5. **`mmap`, and the memory family completed.** ✅ *Delivered 2026-08-20 — see the record
   below. Signals moved to step 6 when the fault path turned out to need more than an
   extension.*
6. **Signals and the fault path** — the hard one: the faulting thread must be parked and the
   adapter woken. ✅ *Delivered 2026-08-20 — see the record below.*
7. **Signals move entirely** — the dispositions, the delivery, the decision. ✅ *Delivered
   2026-08-20; see the record below.*
8. **The calls a message cannot carry** — `clone` and `rt_sigreturn`, over a staged register
   frame. ✅ *Delivered 2026-08-20 — see the record below.*
9. **The identity, scheduling and ending calls** — `gettid`, `arch_prctl`, `sched_yield`,
   `exit`, `exit_group`. The ratchet reads **2**. ✅ *Delivered 2026-08-20 — see the record
   below.*
10. **`futex` and `write`**, then delete what is left of `mod linux`. Each needs a capability
    the adapter does not hold — a notification pool and a console — so this step is a grant
    before it is a translation. The ratchet reads **0**, and T11's mitigation column becomes
    true. ✅ *Delivered 2026-08-20 — see the record below.*
