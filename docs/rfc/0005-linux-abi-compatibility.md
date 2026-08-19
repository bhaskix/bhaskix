# RFC 0005: Linux ABI compatibility as a domain personality

| | |
|---|---|
| **Status** | **Draft — revised for implementation 2026-08-19** (drafted before M5 existed; see "The machine this now lands on" below for what two phases changed) |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (dispatch tag only), userspace; new subsystem `personality` |
| **Milestone** | Phase 2's last bullet — the roadmap's `libc` item, which this RFC resolves into a personality rather than a library |
| **Depends on** | RFC 0008 (the native ABI this must never leak into), RFC 0013 (the service domain it runs as), RFC 0015/0016 (the filesystems Tier 1 translates onto), RFC 0018/0020/0027 (the network Tier 2 translates onto), RFC 0026 (the telemetry plane the `-ENOSYS` log rides). [RFC 0003](0003-storage-architecture.md)/[RFC 0004](0004-ot-security-gateway.md) remain drafts and remain motivation, not dependencies |

---

## The machine this now lands on (revision of 2026-08-19)

This RFC was drafted when Bhaskix was at M4 — no user mode, no filesystem, no network.
Every prerequisite it named has since shipped, and three of its guesses are now facts
with numbers:

- **User mode, domains, capabilities** (M5, RFC 0017): domains are cheap enough that
  question 4's "how heavy do domains turn out to be" has an answer — a supervisor
  creates, grants, starts and reaps one in ring 3 as a demonstration. Per-process
  personality domains are affordable; the question stays open only on isolation grounds.
- **The ELF loader** (M6, RFC 0028): static ELF64, fuzz-hardened through 10.97 billion
  executions, extracted to a leaf crate three consumers share. The loader half of "the
  initial process image" exists; the auxv/stack builder does not.
- **Filesystems** (RFC 0015/0016) and **network including sockets** (RFC 0018–0029):
  Tier 1 and Tier 2 translate onto real services now, not planned ones. The sequencing
  note "Tier 2 cannot start before the Phase 2 network stack exists" is satisfied.
- **The telemetry plane** (RFC 0026) is exactly the `-ENOSYS` logging channel the
  failure-behaviour section asked for, typed events and all.
- **Packages** (RFC 0030): the corpus programs this RFC's testing plan defines can ship
  as installable packages with manifests stating their authority — a Linux-personality
  domain's manifest names what the personality may translate onto, which is rule 2 made
  reviewable.

**What has not changed**: the three rules, the tension with RFC 0003, the tiering, the
three hard parts, and the refusals. **What is still owed from outside**: the motivating
workload's trace (implementation step 1) — the tiers stay provisional until a real
binary's histogram exists, and the public corpus is the work queue in the meantime.

---

## Summary

Bhaskix should be able to run **unmodified Linux binaries** by implementing
the Linux `x86_64` system-call ABI as a **personality**: a translation layer
that runs inside an ordinary domain and implements Linux system calls on top
of the capabilities that domain already holds.

The first target is deliberately narrow — **statically linked Go binaries with
`CGO_ENABLED=0`** — because that single constraint removes the dynamic linker,
`libc`, NSS, and locale handling from the problem, and because it is the shape
of the software that motivates this: an existing Go-based security-operations
workload.

This is explicitly **not** a proposal to make Bhaskix a Linux clone, to make
the Linux ABI the kernel's native interface, or to run Docker or Kubernetes.
Those are addressed under "Alternatives" and "Scope", and two of the three
turn out to be the wrong question.

---

## Motivation

### The problem

Bhaskix at M4 can schedule threads on multiple CPUs. It has no user mode, no
processes, no filesystem, and no network. Everything above that is scheduled
work — M5 and M6 and most of Phase 2.

At the end of all of it, Bhaskix will be able to run software written *for
Bhaskix*. That set is empty, and it stays empty by default, because the cost of
porting is paid per-application by people who have no reason to pay it. This is
the failure mode that kills technically sound operating systems: the kernel is
finished and nothing runs on it.

[RFC 0004](0004-ot-security-gateway.md) already commits to a version of this
answer for legacy OT workloads — run the customer's stack underneath a
hypervisor, because they cannot change it. This RFC applies the same reasoning
one layer up, to software that *can* be recompiled but should not have to be
rewritten.

### Why Go, and why statically linked

The immediate motivation is concrete: a Go-based security-operations
application that should run on Bhaskix without being rewritten. But Go is also
the right *technical* first target, for reasons that are not about preference:

| Property of static Go binaries | What it removes from the problem |
|---|---|
| `CGO_ENABLED=0` produces a fully static binary | No dynamic linker, no `ld.so`, no `PT_INTERP`, no relocation processing at load time |
| Go does not link `libc` | No glibc, no musl, no NSS, no locale, no `errno` TLS conventions |
| Go issues raw `syscall` instructions | The compatibility surface is the *kernel* ABI only, which is stable, versioned, and documented |
| Go's runtime is self-contained | Threading, memory, and scheduling are the runtime's own; we supply primitives, not policy |

Compare the alternative of a C program against glibc, which needs a working
dynamic linker, a large `libc`, `ld.so.cache`, and symbol versioning before it
prints anything. **Go is the cheapest possible entry point into binary
compatibility, and it happens to be what we need.** That coincidence is the
argument for doing this first rather than later.

### What happens if we do nothing

Bhaskix reaches Phase 2 with a `libc` — the roadmap already lists one — and
source-compatible software can be *recompiled* for it. That is a real but much
weaker property: it requires the source, a port of every dependency, and a
maintainer willing to track both. It does not run a vendor's binary, and it
does not run the motivating workload without a Bhaskix-specific build.

---

## The tension with RFC 0003, stated plainly

[RFC 0003](0003-storage-architecture.md) §"POSIX is the bottleneck" argues that
POSIX is the wrong primitive, that Linux's imposition of it is what forces
Lustre, Ceph, and DAOS to fight the kernel, and that:

> A kernel written from scratch does not have to make that assumption. **This
> is one of the few places where "we built our own kernel" converts into a
> concrete technical advantage rather than a slogan.**

An RFC proposing a Linux ABI layer looks like it gives that away on the first
page. It does not, and the distinction is the most important thing in this
document.

**The Linux ABI is a personality, not the native interface.** RFC 0003 already
uses exactly this structure for storage: an object store at Layer 0, placement
at Layer 1, and *personalities* at Layer 2 — where POSIX is one row of a table
alongside Object, Key-value, and Block, and is described as costing "full
semantics, and the cost of them, **paid only by callers who ask**".

That last clause is the whole design, and it transfers unchanged to system
calls. This RFC is the same shape applied to the syscall interface:

```
  native capability syscalls  ─┐
                               ├─→  nucleus (capabilities, domains, IPC)
  Linux ABI personality       ─┘
```

Concretely, this means three rules, and the design is worthless without them:

1. **The nucleus gains no Linux-shaped concepts.** No `pid_t` in the scheduler,
   no file descriptors in the object model, no `uid_t` anywhere. The
   personality maintains its own tables and translates.
2. **The personality is a translator, never a source of authority.** A Linux
   `openat` resolves against a filesystem capability the domain was granted. If
   it holds none, the call fails with `ENOENT` or `EACCES`. The personality
   cannot manufacture authority its domain does not have.
3. **Native software never pays for it.** A domain that does not request the
   Linux personality does not link it, does not carry its tables, and is not
   reachable through it.

If those three hold, RFC 0003's claim survives intact: Bhaskix's *own*
interface is still capability-shaped, and the storage stack is still free to be
an object store rather than a VFS. Linux compatibility becomes something the
system *offers*, not something it *is*.

If they are ever relaxed — if a Linux concept leaks into the nucleus because it
was convenient — this RFC has failed and should be reverted rather than
patched.

---

## Step 2's record (2026-08-19): the tag exists, and the refusal is the feature

Implemented as specified, with one narrowing stated: the syscall entry answers a
Linux-tagged domain's calls with `-ENOSYS` **in the kernel** rather than delivering them
to a personality service, because no such service exists yet — the delivery seam arrives
with the first translated call. What exists and is gated per placement: the `Personality`
tag on a domain (a bitmask the entry reads with one relaxed load — the telemetry class
check's cost discipline), the `PERSONALITY` method (`WRITE`-gated like `START`, refused
`SLOT_UNAVAILABLE` once a thread exists), the register contract held exactly (`rax`
carries `-38`; `rdx` is preserved *by not touching the saved frame slot*; `rcx`/`r11`
clobber matches Linux's own), the `foreign` telemetry schema carrying number and `rip` —
the histogram that is this subsystem's work queue — and a hand-assembled Linux probe
(`getpid`, `write`, `exit_group`, then `ud2`, the only honest exit when every exit is
refused) asserting the exact answer, the exact log, the too-late refusal and the tag
dying with its domain. Two findings: the self-test raced its own too-late check and
un-tagged its probe before the thread arrived — ordering by observed effect fixed it —
and the tag guard needed **both** thread counts (the domain table's `START`ed count and
the scheduler's spawn-instant atomic), because a tag change must lose to a thread that
merely exists.

## Step 3's record (2026-08-19): a Linux program reads the image, and finds its entropy

The builder lives in `bhaskix-personality` — a leaf crate of pure arithmetic, zero
`unsafe`, host-tested byte for byte, which is what this RFC's testing plan asked for and
the only way the auxv gets built correctly: an eight-byte slip in a pointer does not fail
visibly, it hands the runtime the wrong `AT_RANDOM`. The kernel calls that builder to
place a real image (arguments, environment, the seven auxv entries Go reads, and sixteen
bytes of `RDRAND` entropy — or a stated fixed pattern on a machine that cannot be
unpredictable, RFC 0021's policy), then enters ring 3 on it. The witness is eighty-one
bytes of hand-assembled Linux code that walks the image exactly as `_start` does — over
`argv`, over `envp`, pair by pair through the vector — and reports `argc`, `AT_ENTRY`,
and the two entropy words it found by dereferencing `AT_RANDOM`. All three match, gated
per placement, and watched red twice: an `AT_RANDOM` pointer moved eight bytes fails the
host test, an `AT_ENTRY` moved sixteen fails the boot gate. Two jump displacements in the
probe were wrong on the first run (a `jne` over fifteen bytes counted as twelve, a loop
back forty-seven counted as forty-five) — hand assembly is exactly as unforgiving as this
RFC's "three hard parts" section warns, which is the argument for the corpus programs
being real binaries rather than more of this. **No vDSO**, as designed: `AT_SYSINFO_EHDR`
is absent and stays absent until a benchmark asks.

## Design

### Where it lives

A **service domain**, per [architecture.md](../architecture.md) §2's relocatable
services, not the nucleus. The syscall entry path in the nucleus dispatches on
a per-domain personality tag; a domain tagged `Linux` has its syscalls
delivered to the personality rather than to the native capability dispatcher.

Running it out of the nucleus is not a stylistic choice. The personality is a
parser for entirely untrusted input — 300-odd system calls with pointer and
length arguments supplied by the process being contained — and it is the
largest single piece of attack surface the project would have. Placing it in a
domain means a bug in it is a compromise of that domain's authority, not of the
kernel.

### The initial process image

Before any system call runs, the process must be started the way Linux starts
one, because the Go runtime reads that state directly:

- **ELF64 static loading.** `PT_LOAD` segments mapped with `W^X`, `PT_GNU_STACK`
  honoured. M6 delivers the loader; this needs no dynamic-linking support.
- **The initial stack**: `argc`, `argv`, `envp`, and the auxiliary vector.
- **The auxiliary vector specifically.** Go's `runtime.sysargs` parses it and
  behaves differently based on what it finds. At minimum `AT_PAGESZ`,
  `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`, `AT_HWCAP`, and `AT_RANDOM`
  — the last supplies the runtime's startup entropy and is not optional.
- **No vDSO.** Omitting `AT_SYSINFO_EHDR` makes Go fall back to real system
  calls for `clock_gettime`. This is a deliberate simplification: a vDSO is a
  shared object we would have to build, relocate, and keep ABI-stable, in
  exchange for latency on a call nothing currently measures. Revisit when there
  is a benchmark that cares.

### The system-call surface, in tiers

The surface is defined by **tracing the actual target binary**, not by reading
a syscall table and guessing. The tiers below are the expected shape and the
implementation order; the authoritative list comes from running the real
workload under a tracing build and recording what it asks for.

**Tier 0 — a static Go binary runs and exits.** Enough to reach `main`, print,
and terminate.

`exit_group`, `write`, `mmap`, `munmap`, `mprotect`, `madvise`, `rt_sigaction`,
`rt_sigprocmask`, `sigaltstack`, `rt_sigreturn`, `clone`, `futex`,
`sched_getaffinity`, `clock_gettime`, `nanosleep`, `sched_yield`,
`getrandom`, `prlimit64`, `gettid`, `tgkill`, `arch_prctl`.

**Tier 1 — files and processes.** `openat`, `close`, `read`, `lseek`,
`fstat`/`newfstatat`, `getdents64`, `readlinkat`, `unlinkat`, `mkdirat`,
`fcntl`, `ioctl` (a small allow-list, not the general mechanism), `pipe2`,
`dup3`, `uname`, `getpid`, `wait4`, `execve`, plus a minimal synthetic `/proc`
covering `self/exe`, `self/maps`, and `self/status`.

**Tier 2 — network.** `socket`, `bind`, `listen`, `accept4`, `connect`,
`sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `getsockname`,
`getpeername`, `shutdown`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`. This
tier cannot start before the Phase 2 network stack exists and should not be
planned as if it can.

### The three hard parts

Everything above is mechanical. These are not, and they are where the schedule
will actually go:

**Signals.** Go depends on signal delivery for correctness, not just for
robustness. It installs a `SIGSEGV` handler and converts null dereferences into
panics; it uses `SIGURG` for asynchronous goroutine preemption (Go 1.14 and
later), so a Go program with signals stubbed out will hang under load rather
than fail visibly. Delivering a signal correctly means building a Linux
`ucontext`/`mcontext` on the alternate signal stack with the exact register
layout Go expects to read and modify, and restoring it through `rt_sigreturn`.
This is the single most unforgiving part of the design and should be built
first, not last, precisely because it is where the design is most likely to be
wrong.

**`clone` and thread identity.** Go creates its own OS threads with
`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS`.
The personality must map a Linux thread group onto Bhaskix threads sharing a
domain, set the TLS base as `CLONE_SETTLS` requires, and give `gettid` and
`tgkill` answers consistent with what `clone` returned. Thread-group exit
semantics — `exit_group` terminating every thread — must be exact.

**`futex`.** Go's scheduler parks and unparks on `FUTEX_WAIT`/`FUTEX_WAKE`
(private). A subtly wrong futex does not produce an error; it produces a Go
program that deadlocks under contention, occasionally, on a machine with more
cores than the one it was tested on. It needs the blocking primitives M5 and
Phase 2 introduce, and it deserves a dedicated stress test rather than
incidental coverage.

### Failure behaviour

- **Unimplemented system call**: return `-ENOSYS`, and *log it through the
  telemetry plane with the caller's name*. The set of calls a real workload
  makes is the specification, and an unimplemented call is the most valuable
  telemetry this subsystem produces. Never silently return success.
- **Malformed pointer arguments**: rejected by the existing `copy_from_user`
  path, which already faults safely via the exception table.
- **Out of memory**: `-ENOMEM`, per the domain's `ResourceEnvelope`. A Linux
  process must not be able to exhaust the host by asking politely.

---

## Scope: Docker and Kubernetes

These are the two questions that get asked immediately, and the honest answers
are different from each other.

### Docker images: achievable, and not via Docker

Running Docker *images* and running *Docker* are separate problems, and
conflating them is the mistake.

An OCI image is a manifest plus tar layers. Running one requires unpacking
those layers into a root filesystem and starting a process in it with the right
isolation. It does **not** require `dockerd`, `containerd`, or the Docker CLI.
[roadmap.md](../roadmap.md) Phase 3 already lists "container runtime — container
domains, OCI image support", and that item plus this RFC is sufficient: OCI
images, run as Bhaskix domains, with the Linux personality supplying the ABI
the image's binaries expect.

Running the Docker *daemon* would instead require Linux namespaces, cgroups v2,
overlayfs, `pivot_root`, seccomp-bpf, netlink, and iptables — a compatibility
surface an order of magnitude larger than this RFC, and one that would replace
Bhaskix's domain model with Linux's. That is not worth doing at any point.

**Position: OCI image compatibility, yes, in Phase 3. Docker daemon
compatibility, no, ever.**

### Kubernetes: not a goal, possibly a consequence

`kubelet` is a Go program. If Tier 2 is complete and a CRI implementation
exists over Bhaskix domains, a Bhaskix node joining a cluster is *conceivable*.
It is not planned, it should not appear on the roadmap, and it should not be
claimed. Naming it as a possibility is useful only so that nothing in this
design forecloses it.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Native Go port** (`GOOS=bhaskix`) | Months of work in someone else's tree; only helps Go; still fails for any program using `cgo` or exec'ing a non-Go tool. It also has to be maintained against Go's release cadence forever. | The ABI layer proves intractable — most likely if signals turn out to be unworkable. Then a native port trades a hard problem for a large one. |
| **Run Linux in a VM** (Phase 3) | Makes Bhaskix a hypervisor hosting the workload rather than the OS running it, so the workload gets none of Bhaskix's properties — no capability confinement, no attestable domain. | Never as a *substitute*; it is complementary. [RFC 0004](0004-ot-security-gateway.md) wants exactly this shape for legacy OT software that cannot be rebuilt, and both can be true at once. |
| **`libc` and source compatibility only** (already on the roadmap) | Requires source, a port of every dependency, and a Bhaskix-specific build. Cannot run a vendor's binary. Go does not use `libc` at all, so it does not help the motivating case. | It remains worth doing for native software; it is not a substitute for binary compatibility, and this RFC should not be read as cancelling it. |
| **A portable runtime instead** (WASM, JVM) | Does not run existing binaries — it runs software rewritten for it, which is the problem restated. | A workload arrives that is already WASM. Then it is additive, not a replacement. |
| **Full Linux ABI, all ~350 calls** | Unbounded, unprioritised, and untestable. Most calls have no caller; some — `ptrace`, BPF, namespaces — imply kernel architecture we have deliberately not adopted. | Never as a goal. The surface should always be defined by traced workloads. |
| **Make the Linux ABI the native interface** | Discards the project's central technical claim (RFC 0003), imports POSIX's scaling limits, and makes Bhaskix a Linux reimplementation — which has no reason to exist. | Never. If this becomes tempting, the project has lost its thesis. |

---

## Impact on existing design documents

| Document | What becomes wrong |
|---|---|
| [roadmap.md](../roadmap.md) Phase 2 | "**libc** — enough for real userspace software" is now ambiguous: it conflates source compatibility with binary compatibility. It should be split into a native `libc` item and a Linux-personality item, with this RFC's tiers. |
| [architecture.md](../architecture.md) §2 | Gains a new service-domain kind. The claim that services are relocatable should be tested against this one, which is the largest service the project will have. |
| [security.md](../security.md) §1 | The threat model gains an in-scope adversary: **a hostile process inside a Linux-personality domain**, attacking through malformed syscall arguments. This is new and must be written down, not assumed covered. |
| [rfc/0003](0003-storage-architecture.md) | Needs a cross-reference noting that its POSIX critique and this RFC coexist — a POSIX *personality* over the object store is exactly what Layer 2 anticipated, and this RFC is the syscall-side counterpart. |

Updating these is part of implementation, not a follow-up.

---

## Security implications

Per [security.md](../security.md) §1. This is the section that should be read
most sceptically, because the answer is not "none".

**New authority: no, by construction — and that must be tested.** The
personality translates Linux calls into capability invocations on the domain's
own CSpace. Rule 2 above is the invariant. It needs an explicit negative test:
a Linux-personality domain holding *no* filesystem capability must fail every
`openat`, and that test must fail if the personality ever acquires a fallback
path.

**New attack surface: yes, and it is the largest in the project.** Several
hundred entry points taking pointers and lengths from a process whose entire
purpose may be to attack them. Mitigations: the personality is a domain, not
nucleus code; argument copying goes through the existing `copy_from_user`
exception-table path with SMAP; and the syscall argument decoder is a
**mandatory fuzz target**, per [coding-style.md](../coding-style.md) §8, before
Tier 1 merges rather than after.

**A new confused-deputy shape.** The personality acts on behalf of the process
it hosts. If it ever holds a capability the hosted process should not reach —
for its own bookkeeping, say — it becomes a deputy that can be tricked into
using it. The rule is that the personality holds no capability its domain does
not already hold. There is no exception to this, including for debugging.

**`ptrace`, BPF, and namespaces are permanently out of scope.** Each is a
mechanism for one process to inspect or modify another, or to reconfigure the
kernel's view of the world. They are incompatible with the capability model,
not merely inconvenient under it.

---

## Performance implications

The translation adds one indirection per system call: dispatch to the
personality, argument decode, capability invocation. For a Go program this
matters on the `futex` and network paths and essentially nowhere else, because
the Go runtime is deliberately economical with syscalls.

The claim to measure — and it is a hypothesis until then — is that a Linux
process on Bhaskix is within **2×** of the same static binary's syscall latency
on Linux for `futex` wake/wait and for a socket round trip. Two benchmarks,
recorded per-commit like the scheduler's, with regressions failing the build.

A slower-than-Linux result on a *native* Bhaskix workload would be a real
problem; on the compatibility path it is a cost we are choosing knowingly.

---

## Testing plan

**Host** (preferred, per [coding-style.md](../coding-style.md) §8):

- Syscall argument decoding and validation, as pure functions over byte
  buffers.
- The auxv and initial-stack builder, checked against a byte-exact expected
  image — this is fiddly, order-dependent, and perfectly host-testable.
- `errno` mapping from native errors, exhaustively.
- Fuzz target over the syscall argument decoder.

**QEMU:**

- A corpus of Go programs of increasing difficulty, each a gate:
  1. `println` and exit — proves Tier 0 loading, `write`, `exit_group`.
  2. Allocate 1 GiB in a loop — proves `mmap`/`madvise` and the heap.
  3. 10,000 goroutines over channels — proves `clone` and `futex`.
  4. Deliberate nil dereference, recovered — proves `SIGSEGV` delivery.
  5. A tight non-preemptible loop with `GOMAXPROCS=1` — proves `SIGURG`
     asynchronous preemption, which nothing else catches.
  6. Read a file and walk a directory — Tier 1.
  7. An HTTP server, hit by a client — Tier 2.
- Each is negative-tested the way the scheduler's gates are: break the
  mechanism, confirm the gate goes red, restore.

**The real gate:** the motivating workload runs. Until the actual Go
application starts, serves, and stays up under load, "Bhaskix runs Go" is not a
claim the project makes — in the README, in a talk, or anywhere else.

**Contributors without the workload** can work against the public corpus,
which is why it is defined as programs rather than as one binary.

---

## Unresolved questions

1. **Which Go versions are supported?** The runtime's syscall use changes
   between releases — async preemption arrived in 1.14, and the transparent
   hugepage probing in 1.21 reads `/sys`. Pinning a minimum version is
   necessary; which one is not yet decided. *Decided by: whoever traces the
   target workload first.*
2. **`CGO_ENABLED=1` ever?** It requires dynamic linking and a real `libc`,
   which is most of the cost this RFC avoids. Probably never, but it should be
   an explicit decision rather than a drift.
3. **How much `/proc`?** Go touches a handful of paths. A synthetic, read-only,
   per-domain `/proc` with a fixed set of entries is proposed; the set is
   undecided, and it should be an allow-list that grows on evidence.
4. **Personality in one domain or one per process?** Per-process is stronger
   isolation and more expensive. Undecided, and it depends on how heavy domains
   turn out to be after M5.
5. **Does `execve` mean anything here?** A Linux process exec'ing another
   binary is common; it implies process creation semantics that do not map onto
   domains cleanly. It may belong in Tier 1, or it may be out of scope entirely.

---

## Implementation plan

Not a schedule — a decomposition, so others can help. Nothing here can start
before M5 delivers user mode and M6 delivers the ELF loader.

1. **Trace the target.** Run the motivating workload under Linux with syscall
   tracing and publish the actual histogram. Every tier below is provisional
   until this exists.
2. **Personality dispatch.** Per-domain personality tag, syscall entry routing,
   `-ENOSYS` for everything, telemetry on unimplemented calls. Merges with no
   syscalls implemented at all — the observability is the deliverable.
3. **Initial process image.** Static ELF load, initial stack, auxv. Host-tested
   byte-exact. Gate: a hand-written assembly binary that reads `AT_RANDOM` and
   exits with a known code.
4. **Signals.** `rt_sigaction`, `sigaltstack`, delivery with a correct
   `ucontext`, `rt_sigreturn`. Before threading, because it is the part most
   likely to invalidate the design.
5. **Memory.** `mmap`, `munmap`, `mprotect`, `madvise` over the existing
   region map, which already makes `W^X` unrepresentable.
6. **Threads and futex.** `clone`, `gettid`, `tgkill`, `exit_group`, `futex`,
   with a dedicated contention stress test.
7. **Tier 0 gate.** Corpus programs 1–5 pass. This is the milestone worth
   announcing: a real Go binary, unmodified, on Bhaskix.
8. **Tier 1.** Files, directories, synthetic `/proc`. Fuzz target mandatory
   before merge.
9. **Tier 2.** Sockets and `epoll`, after the Phase 2 network stack.
10. **The real gate.** The motivating workload runs under load.
