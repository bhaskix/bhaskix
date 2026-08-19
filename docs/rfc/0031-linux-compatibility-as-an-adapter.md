# RFC 0031: Linux compatibility as an adapter, and the containment it must inherit

| | |
|---|---|
| **Status** | ⬜ **Draft** 2026-08-19 — the strategic frame for RFC 0005's implementation, drafted after eight of its steps had already been built. Its purpose is to fix the boundaries **before** the compatibility surface grows large enough that moving them costs a rewrite, so its content is mostly interfaces and refusals rather than code. One exception shipped with it: §6's Test 1 first arm — a hosted program asking for all five native syscall kinds by number, refused five times, and *surviving the one that is `Exit` natively* — because that observation was cheaper to build than to promise |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (the personality boundary only), userspace (the adapter domains), docs |
| **Milestone** | Phase 2 → Phase 4. This RFC spans phases on purpose: the interfaces are Phase 2 work, the applications are Phase 3 and 4 milestones |
| **Depends on** | [RFC 0005](0005-linux-abi-compatibility.md) (the personality this frames), [RFC 0008](0008-syscall-and-ipc-shape.md) (the native ABI compatibility must never leak into), [RFC 0013](0013-service-framework.md) (the service domain the adapter runs as), [RFC 0017](0017-process-management.md) (domains, grants, reaping), [RFC 0012](0012-iommu.md) (the device containment a compromised adapter must not escape), [RFC 0030](0030-packages.md) (the manifest that will state a Linux domain's authority) |

---

## Summary

**Bhaskix intends to run the Linux software ecosystem without becoming a second Linux kernel.**
That sentence has an architectural consequence, and this RFC is that consequence written down:
Linux compatibility is an **adapter above Bhaskix services**, never a reason to reproduce Linux
kernel architecture inside Bhaskix. The adapter translates a Linux process's requests into calls
on capabilities its domain already holds. It never mints authority, and it is never the thing that
decides whether an operation is allowed — Bhaskix decides, by whether the capability exists.

Two invariants follow, and they are the whole of this document:

```text
Linux UID 0                 ≠  Bhaskix unrestricted authority
Linux application compromise ≠  Bhaskix system compromise
```

Neither is a slogan. Each is a property a test can attempt to violate, and this RFC's deliverable
is four such tests plus the interfaces that make them meaningful.

**It also records a drift.** RFC 0005 §"Where it lives" says the personality belongs in a service
domain and gives the reason. Steps 2–8, implemented on 2026-08-18 and 2026-08-19, put it in the
nucleus. That is stated here in full rather than left for a reader to discover, and §5 is the plan
to correct it.

## Motivation

### The problem this solves

RFC 0005 answers *how* to translate the Linux ABI. It does not answer *what the compatibility
subsystem is allowed to become*, and that question has a deadline: every step of RFC 0005 makes the
surface larger, and the shape a subsystem has at ten thousand lines is the shape it keeps.

Three failure modes are available from here, all of them normal, none of them announced when they
happen:

1. **The compatibility layer becomes a second kernel.** A single privileged process that owns every
   Linux process's memory, files, sockets and signals is a monolithic kernel with an extra address
   space. It would have the authority of everything it hosts, and a bug in its `ioctl` path would
   be a bug in all of them at once.
2. **Compatibility erodes the security model one exception at a time.** Every Linux program expects
   something this system does not offer. Each individual accommodation — an ambient path lookup, a
   process that can see another's memory, a capability minted because a call needs one — is small
   and defensible. Their sum is Linux, reimplemented, with the thesis discarded.
3. **Linux privilege is imported along with the Linux ABI.** `root` in Linux means "the checks are
   skipped". If UID 0 inside a compatibility domain becomes anything more than "administrative
   within what this domain was granted", then the first `sudo` in a hosted container is a privilege
   escalation into the host.

### What happens if we do nothing

RFC 0005 continues, correctly, one traced syscall at a time — and arrives at Tier 2 with a
personality that lives in ring 0, has no notion of a Linux process's authority separate from its
domain's, and no test that says what a compromised hosted program cannot do. At that point the
question "is Linux compatibility contained?" has no answer, because nothing was ever built that
could produce one.

### Who has this problem

**Provenance, because it changes how much this document is allowed to settle.** The strategic
framing arrived on 2026-08-19 as material the project lead relayed for consideration, *not* as a
decision taken — and the lead said so explicitly. It is recorded here as a proposal under review,
which is what `Draft` status means and why nothing in this RFC is settled in code.

The framing itself: Bhaskix as a complete Linux *replacement*, never a Linux *reimplementation*.
That is only a coherent goal if the compatibility path inherits the containment — otherwise Bhaskix
ends up with Linux's attack surface and none of Linux's twenty years of hardening, the worst of
both. **The half of this document that does not depend on accepting the framing** is §5: the
personality is in the nucleus and RFC 0005 says it must not be. That contradiction is a fact about
the tree and stands whatever is decided about the rest.

## Design

### 1. The layering, and what each layer may assume

```text
                    BHASKIX OS
                        │
        ┌───────────────┼────────────────┐
        │               │                │
   Native apps    Linux compatibility   VMs
        │               │                │
        │        Linux ABI adapter       │
        │               │                │
        └───────────────┼────────────────┘
                        │
                Bhaskix services
                        │
             Capabilities + domains
                        │
                Bhaskix nucleus
                        │
                     Hardware
```

Read the picture as a statement about *authority*, not about code:

- **Downward is narrowing.** Each layer can reach only what the layer below handed it. The adapter
  holds what its domain was granted, and a hosted process reaches a subset of *that*.
- **The adapter is a peer of native applications, not of the nucleus.** It is drawn beside "native
  apps" deliberately. It has no authority a native program could not be given.
- **Nothing crosses the ring boundary except a capability invocation** — `architecture.md` §0's
  claim, and the Linux path must not become its exception. What crosses for a hosted process is the
  *trap*; what happens next is a message to a service.

### 2. The interfaces to stabilize now

This is the RFC's operative content: five interfaces, small, cheap today, and expensive to retrofit
after Tier 2. **None of them requires the adapter to be moved out of the nucleus first** — they are
what makes moving it a relocation rather than a rewrite.

#### I1 — The personality boundary: one frame, one delivery decision

The nucleus's total knowledge of Linux must be: *this domain speaks a foreign dialect; here is the
register frame; deliver it.* Today it is that plus twenty syscall numbers and their
implementations. The boundary to fix now is the **frame**, not the implementations:

```text
PersonalityCall {
    dialect  : u16,   // which personality; Linux is one
    number   : u64,   // the dialect's call number, uninterpreted
    args     : [u64; 6],
    thread   : ThreadId,
    domain   : DomainId,
}
```

Two rules, both testable:

- **The nucleus does not interpret `number`.** It is carried, logged (RFC 0026's `FOREIGN` event
  already does this) and delivered. Every `match` on a Linux syscall number in `kernel/` is a
  boundary violation, countable by `grep`, and the count is a gate.
- **The reply is a value and an errno, never a capability.** A personality may not hand a hosted
  process a capability, because a process that cannot name capabilities cannot be given one — see
  I3.

#### I2 — Every Linux object is a capability the adapter holds *on behalf of* a process

A Linux file descriptor, mapping, socket, timer or signal disposition is a row in a per-process
table inside the adapter. Each row's authority is a Bhaskix capability. The rule:

> **An adapter may only put in a row a capability it already held or derived from one it held.**

There is no path from "a Linux call needs authority" to "authority is created". `openat` on a path
the adapter's directory capability does not cover fails with `EACCES`, and it fails because the
capability does not exist, not because a check said no. This is the difference between a permission
system and a capability system, and it is the property that makes Test 1 meaningful.

#### I3 — A hosted process holds no Bhaskix capabilities and cannot name one

A Linux process's CSpace is **empty**. It has no way to express a capability invocation: its
`syscall` instruction is claimed by the personality, and RFC 0008's six kinds are not reachable
through a Linux syscall number. This is already true by construction today and must stay true — it
is why a compromised hosted program cannot forge, derive or invoke anything, and why "creating a
capability" is not on the list of things Test 1 has to defend against dynamically.

The corollary is a refusal: **no "Bhaskix syscalls for Linux programs" escape hatch**, no
`ioctl` gateway to the capability system, no `/dev/bhaskix`. A program that wants Bhaskix authority
is a native program.

#### I4 — A Linux domain's authority is declared, not accumulated

RFC 0030's manifest already states what a package may reach. A Linux compatibility domain gets the
same treatment: its grants are written down before it starts, and the adapter's authority is the
intersection of what the manifest asks and what the granter holds — over-ask refused whole, exactly
as `pkg install` does today. A Linux domain is therefore reviewable in the same way a driver is:
you can see what it can reach without reading the software inside it.

#### I5 — Compartmentalization: one adapter per hosted workload

The adapter is **not** a system service that every Linux process shares. One adapter domain hosts
one workload's process group. Two consequences:

- A bug in the adapter is a compromise of one workload's authority, not of every hosted program.
- Two Linux workloads with different grants cannot reach each other through a shared translator,
  which is the standard failure of a compatibility server.

Shared *code* is fine — one binary, many domains — and is how the service framework already works.

### 3. Where UID 0 lives

`root` inside a compatibility domain means: **administrative within that domain's grants.** It may
chown the files that domain's storage capability covers. It may bind the ports that domain's
network capability covers. It may signal the processes in its own thread group.

It does not gain a capability by being root, because I2 has no path that creates one and I3 gives
it nothing to invoke. There is nothing to "check" for UID 0, which is the point: the confinement is
structural, not a privilege test that could be got wrong.

`setuid` binaries are answered the same way. A `setuid` bit is a request to change a number in the
adapter's own process table; it changes nothing about which capabilities the domain holds.

### 4. What is refused permanently

RFC 0005 already refuses `ptrace`, BPF and namespaces, and those refusals stand. This RFC adds
three of its own, in the same spirit — a refusal with a written trigger is worth more than a
silently unimplemented call:

| Refused | Why | Would reconsider if |
|---|---|---|
| A single system-wide compatibility server | It becomes a monolithic kernel with the union of every hosted program's authority (I5) | Never for the general case; a *stateless* shared service holding no authority of its own is not this |
| Any Linux-facing route to a Bhaskix capability (I3) | A hosted program that can name a capability can be talked into invoking one | Never. A program that wants this is a native program |
| Linux privilege semantics affecting anything outside the domain | Importing `root` imports the model Bhaskix exists to replace | Never |

### 5. The drift, and how it is corrected

**Stated plainly, because the project's rule is that a wrong claim is corrected where it lives.**
RFC 0005 §"Where it lives" says:

> "A **service domain**, per architecture.md §2's relocatable services, not the nucleus. […]
> Placing it in a domain means a bug in it is a compromise of that domain's authority, not of the
> kernel."

As of 2026-08-19 that is not what the tree does. `kernel/src/syscall.rs` contains `foreign_call`,
`foreign_signal_call`, `foreign_memory_call`, `foreign_thread_call` and the `linux` number module;
`kernel/src/signal.rs` builds and restores Linux signal frames. That is on the order of 700 lines
of Linux ABI in ring 0. The pure decision logic *was* kept out — `personality/` is 1,549 lines,
`no_std`, zero `unsafe`, host-tested — which is why the correction is a relocation and not a
rewrite, but the parsing of untrusted pointers and the mutation of address spaces are in the
nucleus today.

Why it happened is worth recording, because it is not carelessness: steps 2–8 needed the address
space, the scheduler and the fault path, and the in-nucleus route was the shortest path to a
*measured* result — a real Go binary making 212 traced system calls, which is what the RFC asks for
and what no amount of design would have produced. The mistake was not writing it down.

The correction has a shape and a trigger, and deliberately does not happen this week:

- **Trigger:** before Tier 1's file surface lands (`openat`, `read`, `getdents64`, synthetic
  `/proc`). Tier 1 is where the adapter starts holding per-process *state* — descriptor tables,
  path resolution, a `/proc` view — and moving stateful code is dearer than moving stateless code
  by an order of magnitude.
- **Shape:** I1's frame becomes a real message to a domain; `foreign_*` moves to `bin/linuxd`
  behind the existing `personality/` crate; the memory calls become RFC 0009 `Memory` operations on
  the hosted domain's space; the signal frame is built by the adapter and installed through a
  narrow kernel operation that takes a frame and a thread, and interprets neither.
- **Kept in the nucleus, and only this:** the dialect tag, the delivery decision, and the
  register frame. Nothing that reads a Linux structure.

Until then, the honest statement — in `security.md` and the tracker, not only here — is that the
Linux personality currently runs with kernel authority, so a bug in it is a kernel bug.

### 6. The security tests

These are the deliverable that makes the invariants more than prose. Each is a boot gate, and each
is **negative-armed**: the gate must be watched failing by a deliberate edit before it is believed,
per the project's standing rule.

**Test 1 — a compromised Linux application.** A Linux-tagged domain, granted one directory and one
socket and nothing else, deliberately attempts, in Linux's own dialect: reading and writing another
domain's memory by address; opening a path outside its directory capability; `mmap` of physical
memory; `ioctl` on a device it was not given; a raw socket; and every RFC 0008 syscall kind
smuggled in as a Linux number. Expected: each refused as an `errno`, no capability created, the
domain's grant set unchanged afterwards, and the refusals visible in the telemetry log.

*Its first arm shipped with this RFC, 2026-08-19.* The `penguin` probe now asks for **all five of
this kernel's own syscall kinds by number** — 0 `Invoke`, 2 `Reply`, 3 `Recv`, 4 `Yield`,
5 `Exit`, each also an ordinary Linux call this personality does not answer — and is refused five
times with `-ENOSYS`. The load-bearing half is the survival clause, which the boot gate demands in
those words: **read in the native dialect, 5 is `Exit`**, and a probe that reported anything after
it did not have its `rax` read as a `Kind`. That is I3 turned from a claim into an observation, and
it is the whole of the route a hosted program could ever have had to the capability interface,
since it holds no capabilities and cannot name one. No new gate — the existing personality gate now
demands the property rather than the self-test's own arithmetic.

*Negative-armed against the mechanism.* One condition added to the syscall entry —
`&& frame.kind != 5`, letting a Linux domain's number 5 reach the native dispatcher — turned the
lane red with the signature the property predicts: the probe was dispatched `Exit` and died before
it could make its remaining calls, so the gate reported *"no foreign calls arrived"*. Reverted, and
green again. A gate that has never failed is a gate nobody has tested.

*What is still missing:* the memory and device arms (they need a second domain to read at, and a
device the probe was not given), and the grant-set-unchanged assertion after the attempts.

**Test 2 — a compromised driver.** Already largely built, and this RFC's contribution is to name it
as one test rather than five gates. Today's tree asserts: a driver in ring 3 cannot make its device
read without a window capability; a revoked object is taken from the *device*, not just the page
tables; a reused device address translates to the object that owns it now; interrupts are remapped
so a device cannot forge one; a domain's death releases its interrupt handlers. What is missing is
a driver that *tries* — a deliberately hostile `bin/blkd` variant aiming DMA outside its window and
being refused by the hardware.

**Test 3 — Linux root.** Inside a compatibility domain, run as UID 0 and attempt to exceed the
domain's grants: mount, `chroot` upward, load a module, open `/dev/mem`, raise its own limits past
the `ResourceEnvelope`, signal a process in another domain. Expected: confined. **Nothing funds
this today** — there is no UID at all — and it is listed as the milestone it is.

**Test 4 — capability revocation.** Already proven and gated: "capabilities: monotone derivation in
rights and badges, immediate transitive revocation"; "two domains share an object, revocation takes
it from both, nothing leaks"; "a lender's death revoked". What this RFC adds is the Linux arm —
revoking the adapter's directory capability must make every descriptor derived from it dead
*before the revoke returns*, which is the property that lets an operator stop a hosted workload
reaching storage without stopping the workload.

### 7. The application milestones

RFC 0005 already uses the word *tier* for **system-call tiers** defined by tracing. To avoid two
meanings of one word, the application targets are **L1–L4** and are milestones, not claims:

| | Target | What it demands beyond the previous | Status |
|---|---|---|---|
| **L1** | Static ELF binaries, BusyBox, shell utilities, `curl`, OpenSSH | Tier 1's file surface, `execve`, pipes, a real `/proc` subset, terminal `ioctl`s | **not started**; a Go binary loads and runs 212 calls |
| **L2** | Python, GCC, Clang, Rust, Go toolchains | The dynamic linker and a real libc's expectations, `fork`, process groups, filesystem breadth | not started |
| **L3** | nginx, Apache, PostgreSQL, MariaDB | Tier 2 sockets and `epoll`, `mmap`-heavy storage, `fsync` durability, users and permissions | not started |
| **L4** | Larger server software, container workloads | Cgroup-shaped resource control mapped onto `ResourceEnvelope`, image formats, orchestration | not started |

The flagship demonstration, when it exists, is: Bhaskix boots → a compatibility domain → nginx +
MariaDB + OpenSSH → network clients connect, with no Linux kernel underneath. **It is a goal. No
document, release note or README may state or imply that any L-row works before a gate proves it.**

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Run Linux in a VM** (paravirtual or full) for compatibility | It is a Linux kernel underneath, which is the thing this is designed to not need. Every containment property becomes the hypervisor's, and the flagship demonstration would be dishonest | Never for the compatibility path. A VM remains the right answer for running an *unmodified Linux distribution*, which is a different product |
| **A single system-wide `linuxd`** | The monolithic kernel of §2 I5: one domain holding the union of every hosted program's authority | A stateless shared service that holds no authority of its own — that is not this alternative |
| **Personality in the nucleus, permanently** | It is the largest untrusted-input parser in the project; in ring 0 every bug in it is a kernel bug. Also what §5 records as an accident rather than a decision | If measurement shows the message boundary costs more than the workload can pay — in which case the RFC is superseded with numbers, not adjusted quietly |
| **Map Linux UID 0 to a Bhaskix "admin" capability set** | Imports exactly the model Bhaskix exists to replace, and makes every `sudo` in a hosted container a host privilege question | Never |
| **Ambient path resolution for hosted processes** (a global `/`) | The ambient root was deliberately deleted at RFC 0016; re-adding it for Linux would make the compatibility path the one place the thesis does not hold | Never. A hosted process's root is a directory capability, which is what `chroot` already means |
| **Do nothing; keep extending RFC 0005 step by step** | Arrives at Tier 2 with no answer to "is it contained", and with interfaces set by whatever was convenient | — |

## Impact on existing design documents

| Document | What becomes wrong, or missing |
|---|---|
| [architecture.md](../architecture.md) | §0 and §2 describe the nucleus and services with no notion of a *personality* — the one thing that dispatches a domain's traps somewhere other than the capability dispatcher. Needs a section, and §8's table needs the new open decision |
| [security.md](../security.md) | §1's threat table has no row for a compromised hosted Linux application, which will shortly be the most likely compromise on the system. §2's guarantee table has no Linux column. Neither states that the personality currently runs in the nucleus |
| [RFC 0005](0005-linux-abi-compatibility.md) | §"Where it lives" is contradicted by steps 2–8; the contradiction is recorded in that document as well as here |
| [roadmap.md](../roadmap.md) | Phase 3 and Phase 4 have no Linux-compatibility milestones; L1–L4 belong there. The first-release section must keep saying what the personality actually runs |
| [TRACKER.md](../../TRACKER.md) | §2 needs the decision row; §4 needs the interface work; §6 needs the four security gates |

Updating those is part of accepting this RFC, not a follow-up.

## Security implications

Reference [security.md](../security.md) §1.

- **New authority:** none. This RFC removes routes to authority; it adds none.
- **Reachable without a capability:** unchanged, and I3 is the statement of why.
- **New parser for untrusted input:** the compatibility surface *is* one, and it exists already.
  This RFC's contribution is to say where it must live (§5) and to require its fuzz targets to
  precede Tier 1, as RFC 0005 step 8 already demands.
- **Scope movement:** adds **T11** — a compromised application inside a compatibility domain — to
  the in-scope table. It also makes an out-of-scope item honest: while the personality is in the
  nucleus, T11 is *not* mitigated, and `security.md` must say so.

## Performance implications

Moving the personality out of the nucleus costs one IPC round trip per hosted system call that the
in-nucleus version does not pay. That is the whole of the cost, and it is measurable before it is
committed to: the existing telemetry `FOREIGN` event and RFC 0026's rings can price a foreign call
in both placements — which is exactly the A/B the service framework was built for. **The number is
gathered before the move, not after**, and if it is unaffordable the RFC is superseded with the
measurement attached rather than quietly not done.

## Testing plan

- **Host:** the personality crate is already host-tested and zero-`unsafe`; the adapter's process
  tables, descriptor translation and grant intersection are the same kind of pure logic and belong
  in host tests. The fuzz targets for the syscall surface are host targets.
- **QEMU:** the four security tests of §6 are boot gates, each negative-armed.
- **Real hardware:** nothing here needs it. (M1-17 remains unmet and unrelated.)
- **Fuzz:** one target per adapter surface that reads process-supplied pointers — the argument
  decoder first, since it is common to all of them.

## Unresolved questions

1. **What is a Linux process, in Bhaskix terms?** One domain per process, or one domain per
   *workload* with several hosted processes inside it? The second is cheaper and weaker; the first
   makes `fork` and `execve` expensive. Decided by whoever implements L1's `execve`, with a
   measurement.
2. **Where does the file-descriptor table live** — in the adapter, or as capabilities in a hosted
   domain's CSpace it cannot name? The second is more faithful to the model and needs the nucleus
   to hold state for a dialect it does not interpret.
3. **Does a hosted process ever get a `Notification`?** `epoll` wants one. Answering yes makes the
   adapter's event loop cheap and puts one Bhaskix concept inside the Linux boundary.
4. **How is a Linux domain's manifest expressed** (I4)? Reuse RFC 0030's grammar, or a Linux-shaped
   one that names mounts and ports? Reuse is the default until something cannot be said.
5. **Cgroup-shaped resource control** onto `ResourceEnvelope` — an L4 question, recorded now so it
   is not discovered then.

## Implementation plan

Deliberately front-loaded with documents and tests, because this RFC's thesis is that the
boundaries must be fixed before the surface grows.

1. **The record.** This document, plus the corrections it names: `security.md` T11 and the honest
   note that the personality is in the nucleus today; `architecture.md`'s personality section and
   §8 row; RFC 0005's contradiction noted in place; roadmap L1–L4; the tracker rows.
2. **Test 1, in its fundable form.** ✅ *First arm delivered 2026-08-19* — the five smuggled kinds
   and the survival clause, gated. Remaining: cross-domain memory, a device it was not given, and
   the grant set asserted unchanged afterwards.
3. **Test 4's Linux arm.** Revoke an adapter's directory capability; assert every derived
   descriptor is dead before the call returns.
4. **I1's frame**, as a type — `PersonalityCall` — with the nucleus's Linux `match` count published
   as a gate, so the boundary violation is visible before it is removed.
5. **Test 2's hostile driver.** A `bin/blkd` variant that aims DMA outside its window, refused by
   the IOMMU rather than by the driver's own good behaviour.
6. **The relocation** (§5), triggered by Tier 1: `bin/linuxd`, the memory calls as `Memory`
   operations, the signal frame built outside the kernel. Priced first.
7. **Test 3**, when a UID exists to test — an L1 milestone, not before.
