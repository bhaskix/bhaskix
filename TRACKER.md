# Bhaskix — Project Tracker

**This file is the single source of truth for project status.** If any other document, issue, or
conversation disagrees with this file about *what is done* or *what is next*, this file wins.

| | |
|---|---|
| **Last updated** | 2026-08-07 |
| **Phase** | Phase 1 — Foundation |
| **Active milestone** | **Phase 2 — Core Operating System.** The service framework (M7), the driver framework (M8) and the full VFS (M9, RFC 0015 and RFC 0016) are complete. **Process management is next** — nothing creates a domain except boot code — then networking |
| **Overall progress** | M1 17/18 (hardware blocked) · M2 MET · M3 COMPLETE · M4 COMPLETE · M5 COMPLETE · M6 6/6 built + M6-07 … M6-18 (RFC 0009 steps 1–6, RFC 0011 COMPLETE, RFC 0012 **COMPLETE**, steps 1–7) · **M7 COMPLETE** (RFC 0013 steps 1–6, M7-01 … M7-15) · **M8 COMPLETE** (RFC 0014 steps 1–6) · M9-01 … M9-26 (RFC 0015 steps 1–6, RFC 0016 steps 1–5 — **COMPLETE**) · CI green · 495 suite checks · 46 boot gates per placement (4 placements), 53 with an IOMMU · 332 host assertions |

### Division of responsibility between documents

Keeping these separate is what stops them drifting into contradiction.

| Document | Owns | Changes |
|---|---|---|
| **TRACKER.md** (this file) | *Status.* What is done, in progress, blocked, next. Decision log. Changelog. | Every working session |
| [docs/roadmap.md](docs/roadmap.md) | *Scope.* Milestone definitions and exit criteria. | Rarely — a change here is a scope change |
| [docs/rfc/](docs/rfc/) | *Rationale.* Why a design decision was made, and what was rejected. | Per accepted decision, then immutable |
| [docs/*.md](docs/) | *Design.* How subsystems work and their invariants. | With the code that changes them, in the same PR |

---

## 1. Working rules

These are the process rules for this project. They are binding.

1. **Update this file in the same change that changes reality.** A task moves to `DONE` in the PR
   that makes it done — never in a separate "update the tracker" commit. A tracker updated
   retroactively is fiction.
2. **`DONE` requires the exit criterion to pass**, not the code to exist. Criteria are in the task
   table and are things a stranger can run.
3. **Every task has a verifiable exit criterion.** If you cannot write one, the task is not
   understood well enough to start.
4. **Blocked means blocked.** Record what it is blocked on and who can unblock it. A task sitting in
   `IN PROGRESS` for weeks is a lie; move it to `BLOCKED` and say why.
5. **Design decisions go in the decision log below**, with an RFC number. "We discussed it" is not a
   record.
6. **Every bug fix adds a regression test** ([docs/coding-style.md](docs/coding-style.md) §8).
7. **No task is `DONE` with a failing or skipped CI gate.** Gates are listed in §6.
8. **Scope changes go to [docs/roadmap.md](docs/roadmap.md) first**, then here. Adding work to a
   milestone without updating its definition is how milestones stop meaning anything.

### Status legend

| | |
|---|---|
| `TODO` | Defined, not started |
| `WIP` | Actively being worked on |
| `REVIEW` | Code complete, in review or awaiting verification |
| `BLOCKED` | Cannot proceed — blocker recorded |
| `DONE` | Exit criterion verified passing |
| `DEFERRED` | Consciously moved to a later milestone, with a reason |

---

## 2. Decision log

Architecture decisions. Once `Accepted`, a decision is not revisited without a superseding RFC.

| ID | Decision | Status | Resolution | Record |
|---|---|---|---|---|
| **N1** | **Project name** | ✅ **Accepted** 2026-08-02 | **Bhaskix**, superseding the working name *VyomOS*. From *bhāskara* (भास्कर, "light-maker"/the sun) and the mathematician-astronomers Bhāskara I and II; `-ix` for the Unix lineage. Coined, therefore ownable — unlike a dictionary word. | [RFC 0002](docs/rfc/0002-project-name.md) |
| **A1** | **License** | ✅ **Accepted** 2026-08-02 | **Apache-2.0.** Permissive for maximal enterprise and government adoption; explicit patent grant, which MIT lacks and which matters for a project inviting corporate contribution. | [RFC 0001](docs/rfc/0001-license-apache-2.0.md) |
| **D1** | Implementation language | ✅ Accepted 2026-08-02 | **Rust** (`no_std`, edition 2024) + minimal asm. Chosen over C, Zig, C/Rust hybrid. Memory safety must be structural to satisfy the security principle. | [docs/architecture.md](docs/architecture.md) |
| **D2** | Boot mechanism | ✅ Accepted 2026-08-02 | **Limine protocol**, isolated behind project-owned `bhaskix_boot::Handoff`. Native `bhaskixboot.efi` scheduled for Phase 2. | [docs/architecture.md](docs/architecture.md) §1 |
| **D3** | Kernel model | ✅ Accepted 2026-08-02 | Capability-based **nucleus with relocatable services**. Not a pure microkernel, not a monolith. | [docs/architecture.md](docs/architecture.md) §2 |
| **D4** | Isolation primitive | ✅ Accepted 2026-08-02 | **Domains** — containers and VMs are the same primitive. | [docs/architecture.md](docs/architecture.md) §4 |
| **S1** | Storage architecture | ⬜ Draft | Capability-scoped Merkle-checksummed object store; POSIX as one personality. | [RFC 0003](docs/rfc/0003-storage-architecture.md) |
| **P1** | First deployment target | ⬜ Draft | Operational technology — a hypervisor beneath the customer's existing, uncertifiable OT stack. Reorders the roadmap: virtualization earlier, desktop later, IEC 62443 as the certification path. | [RFC 0004](docs/rfc/0004-ot-security-gateway.md) |
| **K1** | Storage implementation | ⬜ Draft | **Kosh** — RFC 0003's layers made concrete, plus distribution. Elastic from one node, RF=1…n, block/file/object/key-value, asynchronous geo. Commits to the row RFC 0003 marked *not committed*, and is explicit that the first years are single-node. | [RFC 0006](docs/rfc/0006-kosh-distributed-storage.md) |
| **U1** | Live patching | ⬜ Draft | Nucleus-only, stop-the-world quiescence, declared-patchable functions. Narrows rather than expands: service domains restart instead, and A/B reboot stays the default. Its **P0 prerequisites** — a build identifier and an attestation format that can express "image plus patches" — are cheap now and painful to retrofit. | [RFC 0007](docs/rfc/0007-livepatch.md) |
| **C1** | Binary compatibility | ⬜ Draft | Linux `x86_64` ABI as a **domain personality**, not the native interface. First target deliberately narrow: statically linked Go binaries. Answers **A4** by refusing its premise — own ABI natively *and* Linux compatibility as something offered. | [RFC 0005](docs/rfc/0005-linux-abi-compatibility.md) |
| **A2** | Syscall ABI shape | ✅ **Accepted** 2026-08-04 | **Capability invocation**, six syscall kinds, all authority arriving as a capability argument. A numbered table is ambient authority and discards the project's central claim on the first syscall. | [RFC 0008](docs/rfc/0008-syscall-and-ipc-shape.md) |
| **A3** | IPC style | ✅ **Accepted** 2026-08-04 | **Synchronous rendezvous** is primitive; async is shared memory plus a notification capability, one layer up. Buffering forces the nucleus to answer "whose memory is it", and every answer is a denial of service or the synchronous behaviour with extra steps. | [RFC 0008](docs/rfc/0008-syscall-and-ipc-shape.md) |
| **A4** | Userspace ABI | ✅ **Accepted** 2026-08-04 | **Capability-shaped**, and the native ABI *is* A2's syscall interface — there is no separate document to write. Consequence: no native `libc`; the roadmap's Phase 2 libc belongs to the Linux personality. | [RFC 0008](docs/rfc/0008-syscall-and-ipc-shape.md), [RFC 0005](docs/rfc/0005-linux-abi-compatibility.md) |
| **SM1** | Shared memory | ✅ **Accepted** 2026-08-04 | A **`Memory` object**: frames a capability names, mapped into the holder's *own* address space with rights no wider than the capability, unmapped from everywhere before a `revoke` returns. Completes RFC 0008's answer to **A3** — which promised shared memory and did not build it, so bulk data currently moves sixteen bytes per round trip. Its one architectural fork — whether `Untyped` memory exists at all — **was resolved by acceptance**: it does not. | [RFC 0009](docs/rfc/0009-shared-memory.md) |
| **NF1** | Notifications | ✅ **Accepted** 2026-08-04 | A **`Notification` object**: one word of pending badge bits, at most one waiter, signalled without blocking and safely from an interrupt handler. Completes the other half of RFC 0008's answer to **A3**. Its immediate consequence is that `virtio-blk` can stop polling and `input.rs`'s hand-written reader becomes an instance of a general object. Interrupt *delivery* is ready; who may *claim* a line needs an `IRQHandler` object and its own RFC. | [RFC 0010](docs/rfc/0010-notifications.md) |
| **IR1** | Interrupt authority | ✅ **Accepted** 2026-08-04 | **`IrqControl`** hands out **`IrqHandler`** capabilities, one per source, exclusively. Delivery is mask → signal a notification → acknowledge, with nothing else in interrupt context. Makes `driver-model.md` §2's `IrqCapability` real and gives the kernel a vector allocator instead of five constants in four files. **A domain may claim only MSI-X sources**, because a never-acknowledged shared line wedges other devices. Delegating to a domain remains blocked on an IOMMU (RFC 0012, draft), and the RFC says so rather than implying otherwise — **steps 1–4 are unblocked and worth doing alone.** | [RFC 0011](docs/rfc/0011-irq-handler.md) |
| **IO1** | IOMMU | ✅ **Accepted** 2026-08-04 | **`IommuControl`** hands out **`DmaWindow`** capabilities; a window maps RFC 0009's `Memory` objects and returns a **`DevAddr`**, a type distinct from `PhysAddr`. Funds **T3** and **T4**, which `security.md` §1 claims and the code does not deliver. VT-d first, because QEMU emulates it and a design CI cannot test will be wrong unnoticed — an AMD machine runs degraded and says so. **Roadmap changed on acceptance**: discovery, per-device domains and strict mapping moved from Phase 3 to Phase 2; interrupt remapping and nested translation stay. | [RFC 0012](docs/rfc/0012-iommu.md) |
| **SF1** | Service framework | ✅ **Accepted** 2026-08-05 | The trait, the two placements, the build selection, and the CI job that builds **both** for every service. `architecture.md` §2 has claimed relocatable services since Phase 0 and **none of it exists** — no trait, no placement selection, no service that has ever run outside the nucleus. Could not have been written before M6-18: until the bulk path used shared memory the two placements were identical *by accident*, because four registers map into nobody. Acceptance decides two of its four open questions — the nucleus placement dispatches **through IPC** rather than by direct call, and the placement table is a **build-time** input with a command-line override for tests only. Two stay open: a caller whose service died blocks for ever (the fix needs an endpoint that reports revocation), and whether the console is honestly relocatable at all. Acceptance also corrected `architecture.md`, which described both of this RFC's safeguards in the present tense when neither existed. | [RFC 0013](docs/rfc/0013-service-framework.md) |
| **CR1** | A capability in a reply | ✅ **Accepted** 2026-08-07 | **A reply may carry a capability.** A server answering a `Call` already holds exactly the right authority and nothing more — a one-shot obligation naming the one thread that asked, valid only while it waits — so `HAND` goes on the **endpoint**, because there is no reply capability to put it on: `ObjectKind::Reply` exists but a server never holds one, which makes "not answering anybody" a check rather than a lookup. Where a handed capability lands comes from the **caller's** `EXPECT`, one-shot and addressed to the endpoint it was made for, so a hostile service cannot fill a slot a program was keeping empty. **Badges are one-way**, and this is the rule the rest depends on: any holder with `DERIVE` could previously derive a badge of its choosing, so every use of a badge to say *who is calling* or *which object* was unsound. Two places in the tree demonstrated the hole as a feature and had to be rewritten. It has since refused two wrong things written by its own author while building RFC 0017 — the strongest evidence a rule of this kind can produce. **`ObjectKind::Directory` and `ObjectKind::File` are deleted**; a directory a program holds is a badged endpoint capability to a filesystem service, and `kernel/src/namespace.rs` is gone. All six RFC 0015 step 4 shell gates pass unchanged, which is how we know it is the same claim. Two of four open questions closed; **what ends a lending stays open** — step 5 lends a frame and nothing gives it back. | [RFC 0016](docs/rfc/0016-capability-in-a-reply.md) |
| **PM1** | Process management | ✅ **Accepted** 2026-08-07 | **Create, grant, start, kill, reap** — each an operation on a capability, none a new syscall kind. No `fork` (it duplicates a capability space by implication, which is ambient authority through the back door), no pid (the process tree is the capability tree), no signals ("stop" is `KILL` on a capability you hold; "something happened" is a `Notification`). `DomainControl` hands out `Domain` capabilities, the shape RFC 0011 and RFC 0012 already use. Accepted with **all six steps implemented and gated**, which is why it is accepted rather than argued: four of its own claims were wrong and were corrected by building them — the process tree was *not* transitive over created domains, `GRANT` to a domain did not exist, a ring 3 fault cost a **processor** rather than the machine, and a domain handle must **not** derive from that domain's root. Each correction is written into the document in place. Acceptance decides one open question — a thread spinning inside the kernel is a kernel bug and no mechanism will be built to interrupt it. Three stay open, plus a fourth the implementation added: whether a domain should end when its last thread exits *whoever made it*, which needs the boot sequence to stop treating a domain as outliving its threads. Answers **RFC 0013's unresolved question 1**, open since M7, and closes **M5's exit criterion**, which had been false and untested since M5. | [RFC 0017](docs/rfc/0017-process-management.md) |
| **A5** | 5-level paging (LA57) | ⬜ Open | Support from day one, or assume 4-level and parameterise? | **Did not block M3, and that is the problem.** M3 is complete and shipped with 4-level paging, so the decision was made *by default in code* — which is precisely what Phase 0 exists to prevent. It is recorded as open rather than back-dated to "accepted": nobody weighed it. The cost of deciding it properly rises with every address-space path written against a fixed depth |

> **Correction to an earlier note:** A2–A5 were previously recorded in `roadmap.md` as blocking M1
> exit. They do not — M1 is boot and output, which none of them touch. The real gates are as shown
> above. A1 blocked *accepting external contributions*, and is now resolved.

---

## 3. Milestones in detail — newest first

**Threads exist and the timer preempts them.** The exit criterion is not met and will not be until
SMP lands — it requires N threads across M CPUs, and there is one CPU.

**Milestone exit criterion** ([docs/roadmap.md](docs/roadmap.md) M4): N threads across M CPUs,
10⁷ ping-pong iterations, no lost wakeups, no stranded threads, lock-rank assertions clean;
fairness within 2% for two equal-weight workloads.

| ID | Task | Status | Verified by |
|---|---|---|---|
| M4-01 | `Context` and `bhaskix_context_switch` | ✅ `DONE` | Threads run and resume correctly |
| M4-02 | Per-thread guarded kernel stacks | ✅ `DONE` | Each thread gets its own slot with a guard page |
| M4-03 | Round-robin runqueue | ✅ `DONE` | 7/7/7 runs across three workers |
| M4-04 | Timer-driven preemption | ✅ `DONE` | **Negative-tested**: removing the `preempt` call zeroes every worker counter |
| M4-05 | SMP bring-up, per-CPU areas | ✅ `DONE` | 1, 2, 4 and 8 CPUs all come online; boot test asserts N-of-N. Secondaries schedule as of M4-06. |
| M4-05b | Per-CPU GDT and TSS | ✅ `DONE` | Each CPU builds its own, with its own IST stacks; secondaries now idle with interrupts *enabled* |
| M4-06 | Per-CPU runqueues | ✅ `DONE` | One lock-per-CPU queue; threads are *owned* by a CPU. **Negative-tested**: forcing every thread onto CPU 0 fails the gate. |
| M4-06b | Work stealing and migration | ✅ `DONE` | Idle pull plus load-aware placement. **Negative-tested**: each of the three steal rules and the imbalance threshold has a unit test that fails when that rule alone is removed. |
| M4-06c | Topology-aware balancing, periodic push | ⬜ `TODO` | No ACPI topology, so every CPU is equidistant; balancing is pull-only. `docs/scheduler.md` §5.1 and §5.3. |
| M4-07 | Fair class (virtual deadline), RT class | ✅ `DONE` | Strict class priority, weighted fairness (3:1 measured 2.7–3.1x), FIFO/RR, admission control at 95%. **Negative-tested**: 13 unit tests over the pure pick, each failing when its rule alone is removed. |
| M4-07b | Priority inheritance, domain-level fairness, EEVDF lag | ⬜ `TODO` | PI needs a sleeping lock with an owner; domain fairness needs M5. A crude lead bound stands in for lag. |
| M4-08 | Lock ranking | ✅ `DONE` | Rank given at construction, so a lock cannot be added without one. ~7,400 acquisitions checked per boot, 0 violations. **Negative-tested**: mis-ranking a real lock produces violations; disabling the detector fails the "detector verified" claim. Deviates from "panic" — see `docs/coding-style.md` §7. |
| M4-09 | Sleeping, wait queues, blocking | ✅ `DONE` | `Blocked` state, `WaitQueue`, cross-CPU wake. Ring self-test over 4 CPUs. **Negative-tested**: disabling `wake` gives laps `[1,1,1,0]`, 0 wakeups. |
| M4-09b | Reschedule IPI on wake | ✅ `DONE` | Required by M4-10: a tickless CPU can only be woken by an interrupt. Ring throughput rose from 84 to 736 laps. |
| M4-10 | Tickless idle, one-shot timers | ✅ `DONE` | One-shot APIC timer, per-CPU deadlines, `sleep_micros`, reschedule IPI. **0 ticks over 400 ms idle vs 320–483 busy**; negative-testable as a ratio. |
| M4-10b | Hierarchical timer wheel, TSC-deadline, HPET fallback | ⬜ `TODO` | A wheel needs a many-short-timers workload to have a shape; there is no network stack. |
| M4-11 | TLB shootdown | ✅ `DONE` | IPI to all-but-self, sender waits for every acknowledgement. **Negative-tested**: disabling the receiving handler turns 8 completions into 8 timeouts. |
| M4-12 | Per-CPU frame reserve for the fault path | ✅ `DONE` | Lock-free per-CPU reserve; the fault path no longer touches the allocator. **Negative-tested**: emptying the reserve makes a fault under the lock report `no frame in this cpu's reserve`. |



### M9 — Filesystem ([RFC 0015](docs/rfc/0015-filesystem.md))

| ID | Task | Status | Notes |
|---|---|---|---|
| M9-01 | RFC 0015 step 1: the block driver becomes a service | ✅ `DONE` | `bin/blkd` answers `block::READ` on an endpoint the kernel gave it, over **RFC 0009's bulk path** — the caller names memory it already holds and the driver asks the kernel to fill it, so no sector data crosses in message registers. The criterion was an oracle rather than self-consistency: the Makefile writes `BHASKIX-DOMAIN-DISK-SECTOR-0` into sector zero of the disk the *domain* drives, and the kernel checks that is what came back **without being able to read that disk itself** — it drives the other one. A sector past the end is refused. Granted only where a unit contains the device, so a machine without one gets a driver and no service, which is the refusal working. Watched failing by having the service claim 512 bytes it never delivered. |
| M9-02 | The IPC test that had been wrong twice, and blamed on load both times | ✅ `DONE` | `replies 9, correct 8` had failed twice and been recorded as unexplained. It was the test's own bookkeeping: `REPLIES` was incremented *before* the value was checked and `CORRECT` after, and the waiter woke on `replies >= 8` — the first of the pair — so a client preempted between its own two increments printed `9/8`. The property is **that no reply was wrong**, which is one number; asking it as `correct == replies` asked two counters that were never sampled together. Now the verdict is recorded before the reply is counted, and the gate reads `0 wrong`. |

| M9-03 | RFC 0015 step 2: the on-disk format, on the host | ✅ `DONE` | A superblock, a free-block bitmap, inodes with direct blocks and a generation, and directories as fixed entries — **1,003 lines including the image tool, with no kernel involvement at all**. Nine host tests, one of which flips every bit of every metadata byte and asserts nothing panics. The `mkfs` tool builds an image the format reads back: two files, contents intact. `unsafe` budget zero, which is the standard `ustar` is held to and for the same reason: a disk is bytes somebody else wrote. |
| M9-04 | Three negative tests that did not bite, and why | ✅ `DONE` | Every one of the first three deliberate breakages **passed**. Not because the properties were false but because each was guarded twice: the entry length is clamped in `read` *and* in `name()`; the allocator's floor is backed by the bitmap `format` marks; and one range clause was covered by whichever of the four ran first. Each test now targets the guard it names — the stored field rather than the accessor, a bitmap cleared through `set` so only the floor stands, and one case per clause. All three now fail for their own reason and only their own. This is the fourth time this milestone that redundancy hid an untested check. |

| M9-05 | RFC 0015 step 3: the format mounts in a machine, beside the archive | ✅ `DONE` | The image is a **member of the archive**, which makes "beside" literal: the machine mounts both and reads a file from each. The bytes it reads are in no other file on the machine, and the same name is asserted **absent** from the archive — that is what makes it two filesystems rather than one read twice. Read-only, and in that order deliberately: the format is proved by reading an image built elsewhere before anything may write one, so a bug in a writer cannot be mistaken for a bug in the reader. Four more host tests, including a block pointer off the end of the image, which must read as absent rather than as whatever is at that offset. Watched failing by letting a read run past the size the inode declares — which fails the host test **and** the boot gate. |

| M9-06 | RFC 0015 step 4: directories are capabilities, and there is no root | ✅ `DONE` | A new object kind and one method: `OPEN_AT` resolves **one** name inside a `Directory` capability the caller was given. There is no call that takes a path and no capability naming a root, so a program reaches what it holds and whatever is under it. The shell is handed `sub` and **not** the directory above: it opens `inner`, and `greeting` — same filesystem, one level up, read by the kernel at boot — comes back as "no such name", with no check to forget, because it holds nothing that names the directory it is in. A capability names an inode **and** a generation; nothing writes yet, so the kernel manufactures a stale one to prove the check works *before* the step that can produce one. Watched failing four ways, including handing the shell the root instead — where the containment gates fail by **succeeding**: `greeting: a file of 43 bytes`. |

| M9-07 | RFC 0015 step 5: writes, and a journal that survives an interruption at every write | ✅ `DONE` | Write-ahead, metadata only: payload into the log, **commit**, then home, then clear — and "acknowledged" is defined as *the commit block was written*, because "the call returned" cannot be tested on a machine that stops. The harness stops at **every write of every operation** and asserts the filesystem mounts and holds exactly the transactions that committed — not "before or after", which would pass a filesystem that had applied half of a second transaction. Also run with the writes **reordered** within each phase, and with the recovery itself interrupted, because replay must be idempotent or the ordering is not sufficient. A read-only mount now **refuses** an image with a pending journal rather than handing back the state before an acknowledged operation. Found while building: beginning a transaction over a committed one destroys it (an error path can reach this; a crash cannot), and a block being *allocated* must have its data written before the commit or the file briefly reads its previous owner's bytes. `fs` is still **zero `unsafe`**. |

| M9-08 | RFC 0015 step 6: a page cache, and a filesystem that no longer holds its own bytes | ✅ `DONE` | The cache was the smaller half. The larger half is that until now every structure was read by indexing into one slice, which is only possible because the image happened to be memory — so there is now a **`Store`** (the device: how many blocks, read one, write one) and **`Pages`** (where a block is, right now). An `Image` points into a slice it has; a `Cache` looks, and asks the device when it must. **One** implementation of "what an inode is" sits above that line. Write-back adds one ordering the journal did not need: **the log may not be cleared while a changed page is still dirty**, at the moment everything looks finished — recovery has the same constraint, and without it a survivable crash becomes a lost one on the *second* crash. The interruption moved into the `Store`, so a trace is now what the **disk** saw rather than what the filesystem asked for, and the whole exhaustive harness runs against it. Watched failing four ways, including that missing clear-flush. The *hand a reader a capability to a cached frame* half is **not built**, and the reason is recorded: it cannot be a capability to the cache (that exposes every other block), so it is one frame — which must then be pinned against eviction and revoked when the lending ends, a lifetime only the service owning the cache can see. `fs` is still **zero `unsafe`** across 3,467 lines. |

| M9-09 | RFC 0016 step 1: a badge can no longer be chosen by the program holding it | ✅ `DONE` | A badge is a statement the *granter* made; until this, it was one the holder could make — `derive_owned` took the badge from its argument and `INVOKE`'s `DERIVE` passes that through from ring 3, so any program holding a badged capability with `DERIVE` could call a service as somebody else. Now one-way: a capability with badge zero is a **master** and may set any badge; one that carries a badge may only be derived with the same badge. Rights stay monotone independently, so delegation still works. **Two places in the tree demonstrated the hole as a feature** and had to be rewritten — the capability self-test asserted a re-badged derivation kept the new badge, and `user/probe` forged one from raw ring 3 with a comment calling it "how a derived capability is distinguishable from its parent". Both halves are gated everywhere, because either alone is worthless: delegation under the same badge must work, **and** a chosen badge must be refused. Watched failing in both directions — the rule removed, and the rule made over-strict. |

| M9-10 | RFC 0016 step 2: a reply that carries a capability | ✅ `DONE` | `HAND` on an endpoint, and it is the endpoint because there is **no reply capability to put it on** — `ObjectKind::Reply` exists but a server never holds one, so "not answering anybody" is a check rather than a lookup. Four checks: the endpoint proves this thread is a server, the reply obligation says which caller, the capability is one the server holds with `GRANT` **and** `DERIVE`, and where it lands comes from the caller's new `EXPECT` — one-shot, spent by what arrives and dropped when the call ends. Without that last one a hostile service could fill a slot a program was keeping *empty*, which the shell does and one of its tests depends on. Proved with no throwaway service: the **block driver lends the shell its device's configuration page**, ring 3 to ring 3, and the shell maps it and reads `1af4:1042` — a number no service told it. Needed an IOMMU shell-test mode, because the block service only answers where a unit contains the device. **Two of the three refusals were vacuous** and were rebuilt so the named rule is the only one that can refuse. |

| M9-11 | RFC 0016 step 3 (first half): `block::WRITE`, and a journal on a real device | ✅ `DONE` | The debt RFC 0015 step 1 left: it called for `READ` **and** `WRITE` and only `READ` was built, so the journal — whose entire subject is what reaches a disk — had never reached one. A write needs a new kernel primitive, **`DRAIN`**, the mirror of `FILL`: a caller names memory it holds and a service takes bytes *out* of it, checked the same three ways and asking the caller's capability for `READ` where `FILL` asks for `WRITE`, because the right demanded is the one the operation performs. A filesystem is now laid down on the **virtio disk** through the block service in another domain, a file is created through the log, the machine is stopped one *device* write after its commit, and mounting replays it — read back through a cache created seconds earlier holding nothing. Found on the way: `args[1]` (how many sectors) had always been in the ABI and always ignored, so every block was eight round trips; and the journal put **8 KiB on the stack per transaction**, which overflowed a kernel thread's stack and read as a wild jump. |

| M9-13 | A ring 3 thread must be pinned, and now the kernel says so | ✅ `DONE` | Every user program in this system happened to be spawned pinned, and nothing said why. `bin/fsd` was the first that was not, and it corrupted two other domains: the block driver faulted with a null `self` before touching its device, the console service answered one request and stopped, and the shell printed fifteen characters and hung. One cause. `install_kernel_stack` sets `RSP0` from the incoming thread's own kernel stack on every switch — **and returns early when that is zero**, which it is for a ring 3 thread whose privileged stack was installed for a specific CPU. Moved to another CPU, such a thread enters the kernel on **somebody else's stack**. Every entry into ring 3 now goes through `enter_user`, which refuses an unpinned thread and says why; watched failing by unpinning `bin/fsd`, where a day-long silent corruption becomes one line and the shell keeps working. The real fix is a kernel stack that travels with its thread, and that is not this. |

| M9-12 | RFC 0016 step 3 (second half): the filesystem, in a domain, reading a real disk | ✅ `DONE` | `bin/fsd` mounts the disk through the block service and reads a file the kernel wrote into that same filesystem through **its** copy of the same crate — two copies of one parser, one disk, the same answer. The program contains **no filesystem code**: it links `bhaskix-fs` and supplies a `Store` made of system calls, which is the whole return on RFC 0015 step 6. It holds two capabilities — the block service's endpoint and one memory object it maps — and has no registers, no interrupt, no DMA window and no way to name a disk. It starts by default: the defect that made it opt-in was **a ring 3 thread that was not pinned**, and that is now refused at the door rather than avoided. |

| M9-14 | RFC 0016 step 4: the namespace out of the kernel | ✅ `DONE` | Built and working: a `dir::` protocol in the ABI; `bin/fsd` answering `OPEN_AT` with the namespace rules moved out of `kernel/src/namespace.rs` unchanged — one component, no separators, no `..`, a generation checked, and a name outside the directory held answering exactly as one that exists nowhere; badged endpoint capabilities as directory handles, which the kernel stamps and cannot forge; the disk carrying the same tree the shell's gates describe. Watched working from the shell: `8 directory reachable` and `10 stale dir the directory it named is gone`, both through the service. `kernel/src/namespace.rs`, `ObjectKind::Directory`, `ObjectKind::File`, `OPEN_AT`, `NoSuchName` and `BadName` are **deleted**. All six RFC 0015 step 4 shell gates pass **unchanged**, through the service. |

| M9-15 | RFC 0016 step 5: a lent frame is never the one reused | ✅ `DONE` | The rule and the hand-over. A cache frame can be **pinned**, a pinned frame is never chosen for eviction, a cache with every frame lent **refuses** rather than taking one back, and forgetting keeps what is lent — three host tests, the headline one checking the lent frame after **every** eviction. The cache is now eight one-page `Memory` objects rather than one object of eight pages, which is forced: frames are not contiguous, and handing over the whole object is the disclosure being avoided. `bin/fsd` pins the frame holding a file's data and `HAND`s back a **read-only** derivation of that one object; the shell maps it and reads the file's bytes **out of the service's own cache**, nothing copied. **Three negative tests caught nothing and one did**, which is the finding worth keeping: a lend nothing competes for proves nothing, so with `pin` made a no-op the shell still read the right bytes. Churning the cache by its own size was still not enough — the frame just read is the last one an LRU cache gives up. At twice its size a deleted pin is immediate: the shell is handed the **directory** block and both gates fail on the bytes. Lending the whole object caught nothing (there is no whole to lend); lending it writable was caught. |

| M9-16 | The syscall stub returned to user mode on another thread's stack | ✅ `DONE` | The entry stub parked the user `rsp` in **per-CPU** data and restored it from there — one word shared by every thread on the processor. A system call that *blocks* leaves it there while somebody else runs: another ring 3 thread entering the kernel overwrites it, and the first thread then `sysret`s onto **that thread's stack**, in its own address space. Both user stacks live at the same address in their own spaces, so it is mapped and the fault is not immediate: the program reads its own memory at somebody else's offsets. The frame already carried a per-thread copy and the stub threw it away. Two instructions: take it back and repair the slot. Watched failing by restoring the old exit path — twelve gates fail and `bin/blkd` faults exactly as before. |
| M9-17 | The tickless gate was reporting a real defect as a near-miss | ✅ `DONE` | It failed about one run in four on a loaded host — 165 ticks idle against 327 busy, three the wrong side of a 2× threshold — and the threshold was not the problem. **One CPU was ticking flat out with nothing to run, on every boot since M4.** Two CPUs' worth of ticks in a window that should have held one is exactly the ratio that was being read as noise. The cause: `scheduling_self_test` ends with `stop_all()` to freeze the world for reporting, and `start_all()` sat **four tests further down**, so the tickless gate ran inside the frozen window. `needs_preemption_tick` reads a stopped queue through the same `started` flag it uses for *early boot* — keep ticking, the timer is not proven yet — so every frozen CPU armed a slice it had nothing to preempt to, indefinitely. `stop_all` skips contended queues, so only some CPUs froze, which is why one ticked and the others did not. The old gate could not have said this: a machine-wide counter has no term for *which* CPU, and a ratio against a busy baseline has room to swallow one broken processor in three. It also means the **busy half was measuring nothing** — the burner threads never ran, because they were spawned into a stopped scheduler. Now counted **per CPU** (`trap::ticks_on`), asserted against a bound derived from `IDLE_BACKSTOP_MS` rather than a ratio, retried rather than settled-for-a-fixed-time so host load cannot decide the answer, and it reports **why** a CPU is awake — arming reason, and the threads it holds. Idle went from 165 ticks to 1. Six consecutive runs at load average 11–14. Watched failing both ways: a CPU that never goes tickless, and a CPU that stops ticking with work to do. |
| M9-18 | RFC 0017 step 1: a ring 3 fault ends its domain, not its processor | ✅ `DONE` | M5's exit criterion said a user program *"is killed cleanly when it faults"* and the kernel called `halt_forever`. It survived four milestones because **no test in this project had ever faulted from ring 3** — all six injected faults come from kernel mode. The cost was misdescribed twice before it was measured: `halt_forever` halts *the calling CPU*, so a ring 3 fault took that processor permanently — interrupts disabled, so no timer and no IPI could wake it — and leaked the domain, its envelope and its thread. One CPU means the machine; four means a quarter of it per faulting program. Now the report is unchanged and complete, and then the domain is destroyed and the thread exits. Two details that are not optional: interrupts are **re-enabled** before exiting, or `sched::exit` halts a CPU with them off and the fix becomes the bug in different clothes; and every line is printed **before** `destroy`, because destroy is what a waiter watches for and a report finished afterwards arrives shredded through the next three gates — which is what the first version did. Safe to take the domain table and the capability arena in a handler for one reason: the faulting thread was running *user* code, so it holds no kernel lock. Gated as `bhaskix.fault=user`, behind the command line with the other six rather than in the boot sequence — a deliberate exception on every boot would force `shell-test.sh` to stop treating `EXCEPTION` as a failure marker. It runs on **one CPU**, the harder case, where the machine only continues if the dying thread gives the processor back. Watched failing three ways, each with its own signature. |
| M9-19 | RFC 0017 step 2: a destroyed domain takes its threads with it | ✅ `DONE` | `destroy` released a domain's memory, interrupts and capabilities and **left its programs running** — `domain.rs` documented that against itself. Now it marks every thread of the domain and wakes the sleeping ones; each stops at its next safe point, because stopping a thread where it stands can mean freeing the stack it is standing on. **A flag, not a fifth `State`**: a dying thread is still `Ready`, `Running` or `Blocked`, and everything reasoning about runnability, load and eviction must keep seeing it as what it is — a variant would have to be handled by all of them, and the ones that forgot would be the interesting bugs. Host-tested: marking a thread dying does not move the load figure. **Sleeping is refused, not interrupted.** A dying thread is never marked `Blocked` — sleeping is the one state with no next safe point — and waking the already-blocked ones is the mechanism rather than a courtesy, which is most of step 3 arriving early. The gate runs three ring 3 threads in one domain: one faults, one spins making no system call, one does nothing but `yield`. All three must be gone. **The two safe points are not equally provable**: deleting the interrupt-return check is caught at once and the diagnostic names the survivor (`spinner`, which has no other door), while deleting the syscall-return check is **caught by nothing** — a thread returning from a call returns to user mode, where the interrupt check gets it a tick later. Kept for promptness and for step 3, and the code says so rather than implying it is gated. **Kernel stacks are still not reclaimed** — older and larger than this step; `reap_finished` frees the slot and leaves the stack for want of a stack-slot allocator. |
| M9-20 | RFC 0017 step 3: a caller whose server died is told, and step 2's hole | ✅ `DONE` | **RFC 0013's unresolved question 1**, open since M7, and it was not the small step the RFC predicted — writing its test found that **step 2 had a hole**. `take_message_or_block` writes `State::Blocked` directly instead of going through `mark_blocked`, so it never learned step 2's rule: a dying thread asleep on an endpoint was woken, found nothing and blocked again, for ever. Step 2 therefore stopped every thread **except the ones asleep in IPC**, which is most of the interesting ones, and its own gate could not see it because none of its three threads ever blocked. **The obligation is what dies, not the endpoint.** A caller blocked in `Call` cannot work this out for itself — the endpoint is still there, the capability is still good, and something else may serve it tomorrow. So `exit` takes the dying thread's `reply_to` and tells that caller directly, with **`Status::Revoked`** rather than "no such endpoint": a caller that believed the latter would throw away a capability that is still perfectly valid. The gate adds a fourth ring 3 thread that receives and never replies, and a caller outside the domain blocked on that reply. Three breakages, three signatures: no abandonment leaves the caller asleep; no `dying` check in the delivery decision leaves the server alive **and** the caller asleep; reporting the endpoint gone fails only the third check. |
| M9-21 | RFC 0017 step 4: a program creates a domain | ✅ `DONE` | The first thing in this system that lets a program bring an object into existence. `SPAWN` on a new `ObjectKind::DomainControl` creates a domain and installs a capability to it in a slot the caller names; what comes back **holds nothing**, and every power it will ever have is granted afterwards one at a time. That is the whole argument against `fork`, made structural. **Two requirements, neither sufficient**: the capability says who may ask, the envelope's `max_child_domains` — zero by default — says how often. Either alone lets one holder exhaust a 32-entry table, which is **T10** through the door this step opens. Watched failing separately. **An RFC claim was wrong and is corrected.** "Killing a parent already kills its descendants" was false: `create` inserts a domain's root into the arena as a *root*, not derived from its creator's, so revoking the creator stops at the copy it was handed. Measured — the child was still live. `destroy` now walks its children, and the parent link carries a **generation** so a reused slot cannot be mistaken for the parent that is gone. **The badge rule caught its own author twice**: deriving with badge zero from a root badged with the domain's id is refused by RFC 0016 step 1, which broke the first working `spawn` and then silently neutered a *breakage* — revealing that the child-is-empty check was reading a quota counter rather than the child's CSpace. Five breakages, five signatures. |
| M9-22 | RFC 0017 step 5: a program starts a program, and `GRANT` did not exist | ✅ `DONE` | `START` on a `Domain` capability loads an ELF and gives the domain its first thread. The image arrives as a **`Memory` capability the caller holds**, not a filename: the kernel has no business opening files for a program, and a program naming one would be naming authority it does not hold. It is **copied** before being parsed — the object belongs to a program that is still running and may write to it, and parsing headers a third party can change is how a checked bound becomes a stale one. The loading runs on the new thread, so an untrusted image's size is not the caller's syscall latency and a parser is not on the dispatch path. **`GRANT` to a domain answered `NotImplemented`.** The RFC said the creator grants "using the `GRANT` that already exists"; it did not exist, so a created domain could be given nothing and a started program could do nothing at all. Built here, in `HAND`'s two-stage shape because the giver's CSpace and the recipient's cannot be held at once. **What a program gives away, it can take back**, and that cost an afternoon: the gate granted from slot 0, which the probe revokes at the end of its run to prove revocation is transitive — and it is, so the started program found itself holding nothing. A giver that wants what it gave to outlive its own housekeeping must keep a capability it does not intend to revoke. Four breakages. Two caught nothing at first, because the probe never *asked* for the refusals; it now tries to start a program in an endpoint and to give away a capability it may only hold, and both are refused with their own status. |
| M9-23 | RFC 0017 step 6: a supervisor in ring 3, and two design errors it found | ✅ `DONE` | **RFC 0017 is complete.** A supervisor is now five system calls from ring 3: bind a notification to a `Domain`, wait on it, `INFO` for the reason, `RELEASE` for the slot. None of that is a facility for supervising — it is a notification a program already knew how to wait on, and two methods on a capability it holds. **A handle to a domain must not derive from that domain's root.** Step 4 derived it so destruction would revoke the creator's copy; ending a domain revokes its root so no authority outlives it, which took the handle with it — a creator asking what happened was told its capability was revoked, and the slot the kernel had kept could not be reached. Authority *inside* a domain dies with it; a reference *to* one must outlive it. **Method numbers are shared across kinds, and dispatch order decides the winner.** `BIND`, `INFO` and `RELEASE` were all claimed by earlier blocks that resolve a capability their own way and `return` its failure, so a `Domain` invoked with `INFO` was answered by the code for device windows. All three of this step's methods were unreachable. The first fix asked the kind on every invocation and stalled the machine by putting the domain table on the syscall hot path. **Stated, not hidden**: a domain ends when its last thread exits only if a *program* created it — boot self-tests keep using a domain after its thread finishes, and ending those turned passing tests into `NoDomain`. Retention needs a live parent, or a table of 32 fills with corpses nobody can name. |
| M9-24 | RFC 0016's last open question: what ends a lending | ✅ `DONE` | Step 5 shipped a lend with no way back: `bin/fsd` pinned a frame, handed it over, and nothing gave it back. Now `dir::RELEASE` does **both halves** — unpin the frame, and revoke what was handed. Neither is optional: unpinning alone leaves a caller reading a frame the cache may refill with another file's block, which is the disclosure the whole step is careful about arriving a moment later; revoking alone gives the frame back to nobody. **The mechanism is revocation's direction.** It goes *down* the tree and not up, so the service hands from a **lending capability** derived from its own — one per frame — and revoking that reaches the caller's copy without reaching the one the service still uses. Handing straight from its own would have meant the only way to take a page back was to stop using it. Two gates, two breakages, each failing only its own: revoke-without-unpin reports `1 pages still lent`, unpin-without-revoke reports `MAPPED AGAIN`. **The first version of both breakages caught nothing** — the second lend was failing for an unrelated reason, so both gates were trivially true. Found on the way: `REVOKE` needs `Rights::REVOKE`, and `HAND` needs `GRANT` **and** `DERIVE` on what it copies, so a lending capability carries four rights and each is needed by a different party. What is **not** answered: a caller that never gives a page back — the service can still only refuse the next lend. |
| M9-25 | The soak test was unusable, and the regression it reported was not one | ✅ `DONE` | `tests/qemu/soak-test.sh` has existed since M6-08 and is referenced **nowhere**: not in the Makefile, not in CI, not in this file. Its header makes the case for itself — the M6-08 IPC stall *"passed this project's whole suite, every run, for weeks, and then failed fourteen times in forty"* — and nothing ran it. **Its defect: it never stopped a boot.** This kernel does not power off, so every run cost the full timeout whether it booted in fourteen seconds or hung in the first one. That made forty runs seventeen minutes, and made its two failure kinds indistinguishable — with the cap anywhere near the boot time, "did not finish bring-up" counted every boot the *host* had merely slowed down. Now each boot is stopped the moment it reports the milestone: **40 boots in 4m50s instead of 17 minutes**, and the slowest is printed so the cap can be seen not to be near it. `make soak`, not part of `make test`. **And a conclusion of mine that was wrong.** At the old defaults it reported 4 of 40, then 3 of 30, and a pre-RFC-0017 worktree ran 30/30 clean beside it — which I read as a regression from RFC 0017 and said so. It is not: one boot at a time, the current tree booted **20 out of 20, in 14 seconds each, with no self-test failure**. Four concurrent four-processor guests on a loaded host is what failed, not the kernel. |
| M9-26 | The shell test was not flaky: the kernel was tearing the shell's banner | ✅ `DONE` | Caught in the act. The shell's first line came out as `a user-mode s` … two kernel lines … `hell. 'help' lists what it can do.` The shell was **alive and prompting**; the harness was waiting for a contiguous `a user-mode shell` that had arrived in two pieces, and waited until its timeout. **This had been found and half-fixed before.** The comment beside the shell's spawn describes the exact tear and says *"the fix is to stop overlapping rather than to make the test cleverer"* — and it was applied to two of the four remaining kernel lines. The other two lived in the *caller*, after `user_shell` returned, and went on tearing the banner for three milestones. Every occurrence was written off as a loaded host, including **six times by me in this session**, because that is exactly what it looks like. Both lines are now printed before the shell starts. `make test` passes at its **default** timeouts, which it had not done all session. The console-drop check now covers the kernel's own output and not the shell's, which is narrower and is the price of not overlapping. |

### M8 — Driver framework ([RFC 0014](docs/rfc/0014-driver-framework.md))

**What it set out to prove:** that the *third* driver will not repeat the first two. RFC 0014's case
is an invoice — `bin/blkd` cost three bugs the kernel's driver had already learned and written down
in comments — so the test of this milestone is whether those bugs become impossible rather than
documented.

| ID | Task | Status | Notes |
|---|---|---|---|
| M8-01 | RFC 0014 step 1: `Mmio<T>` and `register_block!` | ✅ `DONE` | **`Bus` has no 64-bit access.** Not one used carefully — it does not have one, so a 64-bit register is two 32-bit accesses because there is nothing else it could be. That is bug 1 made *unrepresentable* rather than fixed. Constructing an `Mmio` is unsafe and using one is not, so a driver spends one `unsafe` per block instead of one per access: `blkd` has forty-two. `register_block!` declares offsets once and checks the layout **at compile time** — two negative fixtures, excluded from the workspace because they must not build, and `make gates` asserts they fail *and say why*. Watched failing: removing the overlap check makes the overlapping block compile and the gate says so. Four host tests, one of which is the test that would have caught the bug this RFC exists for. |

| M8-02 | RFC 0014 step 2: the kernel's driver moves onto them | ✅ `DONE` | Twenty-seven register accesses across two structures, declared once as `CommonCfg` and `BlockCfg` instead of a module of constants plus six hand-rolled accessors. **The success criterion was that nothing changes** and the boot line is identical: 180 sectors, 2 requests, status 0x0f, 1 wait and 0 spins. **The kernel's `unsafe` count fell 1154 → 1112** — forty-two blocks making the same promise over and over became two, made where the blocks are constructed. The budget was lowered to match, which is the direction it is supposed to move and the first time it has. Four accessors were left dead by the change and deleted; `read8` and `write16` survive, because the request status byte and the queue notification are memory and a doorbell rather than registers in a block. |

| M8-03 | RFC 0014 step 3: a device model to test a driver against | ✅ `DONE` | `bhaskix_device::testing` — a fake **device**, not a byte array. A register file alone answers with whatever was written, which is the one behaviour a real device does not have: real devices *refuse*, and the refusals are what a driver gets wrong. The kernel's own bring-up runs against it on the host — `negotiate` and `take_vector` are the code the machine runs, not a copy — and five tests cover what could previously only be tested by finding a device that said no: a device not offering virtio 1.0 is refused **and told**, one clearing `FEATURES_OK` is believed, `ACCESS_PLATFORM` is taken whenever offered, and `0xffff` for a vector is heard as "no vector". **Each was watched failing for its own reason and only its own.** Ring-level tests wait for step 5, where the queue moves into a crate; saying so beats redefining step 3 to fit what was easy. |

| M8-04 | RFC 0014 step 4: ECAM, checked against the ports | ✅ `DONE` | `MCFG` parsed, the region mapped, and configuration space readable as memory. **The port pair was kept because it is the oracle**, which acceptance decided and this step used: every function on every bus is read *both ways* and the answers must match — **65,536 functions, 8 present, none disagreed**. "The new mechanism found three devices" is not evidence it found the right three. Watched failing by shifting the device field one bit: 135 of 65,536 disagree, reported with the first address. That negative test also found a real weakness — the first version bounded the *bus* and not the computed address, so a wrong shift walked out of the mapping and **faulted**, which is a machine that stops booting rather than a mechanism that reports. It is bounded against the mapping now, and an in-range bus that the arithmetic cannot place counts as a disagreement. |
| M8-05 | Shell tests paced by the machine rather than by a clock | ✅ `DONE` | Three different shell checks had failed under load, each looking like a different bug and all of them being one: commands were typed on a fixed interval that assumed each finished inside it. Every line now waits for **its own echo** before the next is sent. The first line is still resent while unanswered — the prompt is printed before the shell reaches its read — and later lines never are, because the bytes queue in the UART and a resent command would run twice. The suite passed at load average 11.45, which is the load it had been failing at. |

| M8-06 | RFC 0014 step 5: the virtqueue is one implementation, not two | ✅ `DONE` | The split-virtqueue protocol — descriptors, the available ring, the used ring, and **the order the writes happen in** — moved into `bhaskix_device::virtqueue`, which the kernel's driver and `bin/blkd` both compile. Each ring is given twice, as the address the driver writes through and the address the *device* is told, because with an IOMMU those differ and that difference is RFC 0012 from a driver's side. **Nothing changed**: 200 sectors, 2 requests, status 0x0f, and `blkd` still reads `BHASKIX-` and is still woken by its device. Four host tests, each watched failing for its own reason — including the one property no amount of reading the values afterwards can check, that the chain is published **before** the index that makes it visible. **The kernel's `unsafe` fell again, 1112 → 1067.** |
| M8-07 | A byte that vanished from the console, and had been vanishing silently | ✅ `DONE` | A shell test failed on a string that never appeared. The machine had printed `6  ignal rd` — the `s` was gone. `serial::write_byte` gives up after a spin limit and **drops the byte rather than hang**, which is the right choice and was a silent one: under an emulator on a loaded host the UART is slow to report itself empty. It is counted now, and the boot reports whether every byte reached the wire — **gated, because every other check reads that log and this one decides whether they are reading all of it**. Also removed: a `MARK msix readback` debug line that had been shipping in every boot since RFC 0012 step 6. |

| M8-08 | RFC 0014 step 6 COMPLETE: a configuration-space capability | ✅ `DONE` | The driver holds one page of **its own device's** configuration space, read-only, and reports `1af4:1042` from it — the virtio vendor and the modern block device — without asking the kernel anything. The value is only reported when a **writable** mapping of that page was refused, so one number covers both halves of the decision: readable always, writable never, because a writable configuration page is a writable BAR and no IOMMU governs where a device *answers*. Watched failing by removing the rights check. **RFC 0014 is complete.** |
| M8-09 | The open question answered, and the answer was *nothing* | ✅ `DONE` | Acceptance left one question: how much of the command register is mediated. The answer is none of it, and the reason is that the question assumed a driver would ask to become a bus master. It does not — the kernel already enables bus mastering at the one moment it is safe to, after the device is reset and at the same point it grants the DMA window that contains it. A system call whose only effect the kernel performs anyway, at a better time, has nothing to do. The delegable set is smaller than the RFC proposed, because the proposal carried an assumption that turned out to be false. |

### M7 — Service framework ([RFC 0013](docs/rfc/0013-service-framework.md))

Not a milestone `docs/roadmap.md` numbers: Phase 2 lists its work as bullets rather than milestones,
and these are the **service framework** one. The numbering is this document's, so that the tasks can
be referred to at all.

**What it set out to prove**, from `architecture.md` §2: that a service can run inside the kernel or
in a domain of its own, chosen at build time, with the interface not knowing which. That sentence
had been in the design documents since M1 and nothing had ever tested it.

**Status: RFC 0013 is complete, steps 1–6.** Both services run in ring 3, a block driver runs in a
domain of its own, and `services.toml` decides placement at build time. What the milestone did *not*
do is listed under "What M7 did not do" below — it is short, and none of it is hidden.

| ID | Task | Status | Notes |
|---|---|---|---|
| M7-01 | RFC 0013 step 1: the `Service` trait, and the nucleus placement | ✅ `DONE` | `Service`, `Context`, `Request`, `Reply`, and **one** `run::<S>()` loop both services share instead of hand-rolling their own. The success criterion was **no behaviour change** and the boot output is identical — 19 requests, 1 caller refused, 5 entries, 8 bytes, bulk path unchanged. Dispatch is by message in the nucleus too, per the acceptance decision, so the placements differ in *placement* and not in *shape*. Three host tests run the services' logic with no machine under them. The machine now prints `console=nucleus vfs=nucleus`, gated — and that line is **expected to change at step 3**. |
| M7-02 | RFC 0013 step 2: the placement table, and what makes it true | ✅ `DONE` | `services.toml`, and `tools/check-placements.sh` to give it teeth. The console is now **its own crate**, compiled for `x86_64-unknown-none` with **no kernel in the build** — that compile *is* the domain placement's, and unlike a lint it cannot pass by accident. The rule is enforced against the **resolved dependency graph**, not a search for suspicious lines: a service cannot name `crate::vfs` without depending on the kernel. Two negative fixtures, both run by `make gates`: a service that calls into the kernel (must be rejected **naming `bhaskix-kernel`**), and a table wrong about itself (a name listed twice, a placement of `orbit` — **both** must be reported). The boot line is now built from the table, so the machine and the file cannot drift. **What it cost:** the filesystem is `relocatable = false` in the table, in the file rather than in a comment — its bulk path reads caller pages through the direct map, so it does not compile without the kernel. That is step 3's actual work, now named. |
| M7-03 | RFC 0013 step 3a: the filesystem becomes relocatable, and a hole closes | ✅ `DONE` | The filesystem is **out of the kernel crate** — `ustar`, `vfs` and the service in `services/vfs`, building for `x86_64-unknown-none` with no kernel in the build. One function did it: the bulk path used to read caller pages through the direct map and now asks its context (`Bulk::fill`). **A security hole was found on the way and closed:** `Reply` took the caller from a register, so a server — including a ring 3 one, since `Reply` is a system call — could plant a message in *any* thread's mailbox and wake it holding what looked like the answer it was waiting for. The kernel now remembers who a thread received from and refuses anything else, which also freed the register that lets a server receive a whole four-register message at all. `Request::caller` is **gone from the trait**: a service cannot name a caller, so it cannot name the wrong one. Gated, and the gate was watched failing twice before it was believed — see the note below. |
| M7-04 | RFC 0013 step 3: the filesystem runs in a domain | ✅ `DONE` | `bin/vfsd` **is** the filesystem service, in ring 3, holding one endpoint capability and a read-only mapping of the image — and every `fs::` method in the system is answered by it. The user-mode shell now reads files through IPC from a service that is itself unprivileged: two ring 3 programs, with the kernel routing messages and owning neither. The service crate is byte for byte the one the kernel compiles for the nucleus; what differs is the context (`Bulk::fill` is `method::FILL`) and the run loop (`serve::<S>` for `run::<S>`). `services.toml` decides which, through `kernel/build.rs`, and `make test-placements` **boots both, every build** — the placement nobody is running is compiled out, so nothing else would notice it rotting. |
| M7-05 | RFC 0013 step 4: everything in a domain, and the address space that was missing | ✅ `DONE` | Both services run in ring 3. The console holds a `Console` capability — **put a character, take a byte, nothing else** — so a console service talked into misbehaving can still only put characters and take bytes; the same service in the nucleus could do anything. The shell, the console and the filesystem are now three unprivileged programs and the nucleus runs **no service at all** in that build. **What this found:** the kernel kept *one* installed address space for the whole of M5 and M6. With a single user program that is indistinguishable from keeping the right one — two services in domains landed on the same CPU and ran in each other's page table. Threads now carry their page-table root and load it as they resume, and the fault handler asks the hardware which space it is in rather than trusting bookkeeping. All four placement combinations boot and pass, every build. |
| M7-06 | RFC 0013 step 5: what a placement costs, measured | ✅ `DONE` | The three numbers RFC 0013 asked for, per service and per placement. **A domain costs ~5,000 cycles (~2 µs) a round trip, about +48%**, and it is the same +48% for both services — 10.0k→15.2k for the console, 11.3k→15.8k for the filesystem. **Shared memory still pays: 10.3× in the nucleus, 7.3× in a domain** (the domain's bulk path copies through its own buffer and then makes a system call, so it costs twice the nucleus's — and still beats fifteen round trips by seven times). **Boot time is unchanged**, ~7.6 s either way. Measured as the *minimum* of 200 samples, because the first version timed whole loops and produced a nucleus filesystem four times slower than a domain one. |
| M7-07 | The unpinned service that cost 6× | ✅ `DONE` | Chasing that reversed result found a real one: the nucleus filesystem thread was **not pinned**, so every call waited for another CPU to notice it — 66k cycles against 11k for the same code pinned, at the minimum rather than in the tail. It was unpinned deliberately, with a reasonable comment: it blocks on nothing but its own endpoint, so it could run wherever there was room. That was true, and it cost six times the latency. Pinned now, with the measurement as the reason. |
| M7-08 | RFC 0013 step 6a: a domain can map memory it holds | ✅ `DONE` | `method::ATTACH` — a domain maps a `Memory` capability into **its own** address space, at an address of its choosing, from frames the object supplies rather than any it names. Never executable, per RFC 0009. **The first thing a driver in a domain needs:** its descriptor rings are memory it holds and the device reaches by `DevAddr`, and it cannot fill them in without seeing them. Exercised from ring 3 by the shell's new `map` command, which holds **two capabilities to one object** — writable and read-only — so the refusal tests the *right* and not the lookup. Watched failing: with the rights check removed the shell gets a writable mapping of read-only memory and the gate says so. |
| M7-09 | RFC 0013 step 6b: device registers as a capability | ✅ `DONE` | `ATTACH` now takes a `Frame` capability too: one physical page, mapped **uncached and write-through** into the caller's own space, never executable. The kernel mints one for the block device's common configuration window; **the shell reads the device's status register from ring 3 and gets 15** — acknowledge, driver, features-ok, driver-ok, the device agreeing a driver brought it up. It cannot name a physical address, cannot ask for a different page, and is refused a writable mapping of the one it has. Watched failing by mapping one page over: `status 1`, and the gate said so. The second of the three things a driver in a domain needs. |
| M7-10 | A test that had been told not to race, and did | ✅ `DONE` | `notify`'s test module said *"one test, because the slots are a global and cargo runs tests in parallel"* — and had two. The second drained the arena and asserted it came back empty, which it does not when the first is holding a slot. It failed once in a full run and passed on every re-run. A comment asking people to keep to one test was never going to hold; the tests take a mutex now. |
| M7-11 | RFC 0013 step 6c: a domain is woken by a notification | ✅ `DONE` | `method::WAIT` and `method::PEEK` on a `Notification` capability. **The shell, in ring 3, is woken by one and reads the badge** — holding no vector, no interrupt controller and no way to reach either. Taking is once: the second look finds nothing, because a notification is a signal and not a queue. A capability with the write right and not the read right is **refused a take** — same object, weaker capability. The third and last of the things a driver in a domain needs. What the shell is woken by is a kernel signal rather than a device, deliberately: that an *interrupt* reaches a notification is gated where the interrupt is (M5, delegation self-test), and what was missing was only the last link. |
| M7-12 | RFC 0013 step 6: a block driver in a domain, bringing up a device | ✅ `DONE` (bring-up; the data path is next) | `bin/blkd` drives the **second** virtio block device from ring 3. The kernel enumerates the bus and hands over three `Frame` capabilities and a `Memory` object; everything after that is the driver's — it maps its own windows, resets the device, and drives the handshake to acknowledge|driver. It reports **1 sector**, which is its own disk: the kernel's is 180, so a driver handed the wrong device says so in a number nothing else on this machine produces. Two devices because two drivers on one would race resets and interleave rings. **The bus stays in the kernel** and that is not a convenience: PCI configuration space is port I/O, and a domain holding it would hold every device on the machine. Watched failing by removing the handshake. |
| M7-13 | RFC 0013 step 6 COMPLETE: a driver in a domain reads its disk by DMA | ✅ `DONE` | `bin/blkd`, in ring 3, programs a virtqueue with **device addresses it could not have invented**, kicks the device, and reads sector 0 of its own disk: `sector 0 begins "BHASKIX-"`, which is on that image and no other. The DMA goes through a **page table of its own** — RFC 0012's `DmaWindow`, granted to the domain, with its own domain id under the same unit. **The window is granted only when there is a unit to contain it**: without one the driver gets registers and no way to make the device read, because a domain that could aim a device with physical addresses could aim it at the kernel. Three bugs found, all of them things the kernel's own driver already knew — see the note. |
| M7-14 | The delegated device's MSI-X wired to the domain's notification | ✅ `DONE` | The driver in ring 3 is now **woken by its own device**. The kernel claims the MSI-X entry and programs it — an MSI is a memory write of an arbitrary vector to an arbitrary CPU, so that authority is never delegated — and hands over two capabilities: the handler, and the notification it signals. The driver says *which* table entry its queue uses, in a register it holds, and waits; the kernel says what that entry contains. It acknowledges to unmask, which is the whole of a delegated driver's interrupt duty. Gated on `woken by the device`, watched failing by not binding: the read stops working **and** the stray-interrupt detector fires, because the vector is programmed and nobody owns it. |

| M7-15 | The tests that left the suite when the code left the kernel | ✅ `DONE` | `make test-host` and `make clippy` **named their packages**, so when `ustar` and `vfs` moved into a crate of their own at step 3a their tests stopped running — including the archive mutation harness, a million malformed archives. Twenty-two assertions were out of the suite for a day and nothing said so; clippy had never seen the crate either. `--workspace --exclude bhaskix-boot-shim` now: one exclusion, with a reason, instead of a list that has to be remembered. Found by checking the suite's own numbers against the packages rather than by anything failing. |

#### Where M7 ended

| Question | Answer |
|---|---|
| Can a service run in either placement? | **Yes**, and both are booted every build. Four combinations of two services, 46 gates each. |
| Is it the same code? | **Byte for byte.** `services/console` and `services/vfs` are compiled into the kernel for the nucleus placement and into `bin/consoled` / `bin/vfsd` for the domain one. What differs is a context and a run loop. |
| What does the isolation cost? | **~5,000 cycles (~2 µs) a round trip, about +48%**, the same for both services. Boot time unchanged. Shared memory still beats the message path 7–10×. |
| Can a driver run outside the kernel? | **Yes.** `bin/blkd` brings up its own PCI device, reads a sector by DMA through a page table of its own, and is woken by that device's interrupt. |
| What stayed in the kernel, and why? | The bus (PCI configuration space is port I/O), the MSI-X table (an MSI is a memory write of an arbitrary vector to an arbitrary CPU), and the page tables. Each is a thing that cannot be handed over in a smaller piece. |

#### What M7 did not do

- **No supervisor.** RFC 0013 says explicitly that it does not propose one, and it does not have one:
  no restart policy, no health checks, and a service that dies stays dead. The boot waits for the
  block driver's report by looking for it, which is what a supervisor would do properly.
- **The console's driver is still in the kernel.** The console *service* is in a domain and holds a
  `Console` capability — put a character, take a byte — but the thing that talks to the UART is not.
  What that bought is a smaller blast radius, not a smaller kernel.
- **The domain filesystem is handed its image at entry** rather than reading a device. Real storage
  behind a service in a domain needs the block driver to become one, which is the next thing.
- **A domain gets DMA only where there is an IOMMU.** Without a unit the block driver is given
  registers and no window. That is a refusal and not a gap: a domain that could aim a device with
  physical addresses could aim it at the kernel.
- **One outstanding request.** The driver submits one, waits, and reads it. A queue with more than
  one request in flight is not tested and almost certainly not right.

### M6 — Filesystem, ELF, shell

| ID | Task | Status | Notes |
|---|---|---|---|
| M6-01 | Initial ramdisk: bootloader module, `ustar` reader | ✅ `DONE` | First untrusted input the kernel parses end to end. Seeded mutation harness, one million malformed archives, no panic. **Negative-tested**: no module, and one corrupted byte. |
| M6-02 | VFS layer over the initrd | ✅ `DONE` | Paths resolve, files open with a cursor, directories list what is directly under them. `..` is **refused rather than resolved** — it cannot escape a flat archive today, and would be a traversal the moment a backend walks a tree. **Negative-tested**: accepting `..` fails the boot gate. |
| M6-03 | ELF64 loader, with a fuzz target | ✅ `DONE` | Ring 3 now runs `bin/probe`, a separately built ET_EXEC loaded out of the initrd, mapped at the addresses and with the permissions **its own headers** name. **Negative-tested**: dropping one segment fails the gate; a deliberately reintroduced wrap bug is caught by the mutation harness at seed 424. |
| M6-04 | Kernel shell | ✅ `DONE` | The console reads: ACPI walk → I/O APIC → IRQ 4 → a vector → a lock-free ring → a blocking read. Nine read-only commands, run by the boot self-test through the same function the prompt calls. **Negative-tested**: draining one byte per interrupt fails the boot gate; removing the wake-up passes it and fails `shell-test.sh`, which is why that test exists. |
| M6-05 | User-mode shell over the syscall interface | ✅ `DONE` | The machine boots to a shell in ring 3 holding two capabilities and nothing else: console and filesystem, both reached by IPC, sixteen bytes per round trip. `shell=kernel` selects the ring 0 one. **Negative-tested**: withholding the filesystem capability makes `caps` report it, both filesystem commands fail, and everything else keeps working. |
| M6-08 | RFC 0009 steps 1–5: `Memory` objects, mapping, revocation, transfer, the channel | ✅ `DONE` | An object is frames, a length and an owner, charged to a `ResourceEnvelope` and released when it goes; `Backing::Shared` lets an address space borrow frames it does not own. `ObjectKind::Untyped` deleted, per the RFC's acceptance. **Negative-tested**: a `destroy` that leaks four frames fails the gate. The teardown invariant — a destroyed address space must not free a shared region's frames — is asserted directly rather than inferred. Step 3 adds the reverse map, the revocation walk and the shootdown: after `revoke` returns the pages are gone from the *page tables*, which is what grants access. **Negative-tested** twice: a `destroy` that leaks four frames, and a `revoke` that removes the bookkeeping but leaves the page-table entry. Step 4 gives an object a capability that can be granted: two domains reach the same frames at different addresses, the recipient's rights are narrower, and one revoke takes it from both. Step 5 adds the ring layout in `abi`, which touches no memory and keeps that crate's `unsafe` budget at zero. |
| M6-07 | RFC 0011 steps 1–4: a vector allocator, `IrqHandler`, and a driver that stops polling | ✅ `DONE` | One registry for all 256 vectors; `IrqControl`/`IrqHandler` with exclusive claims and reserved sources; the delivery path is mask → signal a notification → acknowledge. RFC 0010's `Notification` landed with it, because step 3 binds one. `input.rs` and `virtio-blk` are both clients now rather than special cases. **Negative-tested**: leaving the notification unbound fails the gate. |
| M6-06 | `virtio-blk` driver | ✅ `DONE` | PCI enumeration, modern virtio 1.0 discovered through the device's own capability list, a split virtqueue driven by DMA. `root=disk` mounts the filesystem off the device, so the user-mode shell is a file the driver read. **Negative-tested**: a driver that ignored the sector number reads sector zero four times and fails the gate, because the disk is the ramdisk image and the kernel has the same bytes from the bootloader to compare against. |
| M6-09 | RFC 0011 step 5: a handler does not outlive its owner | ✅ `DONE` | Destroying a domain is `RELEASE` for every handler it held — collected under the handler lock, released outside it, because masking a line reaches the chip and freeing a vector reaches the allocator and both rank below it. `NO_DOMAIN` is not a spare identifier: the console's and the block driver's handlers belong to the nucleus, and a recycled domain id must not sweep them up. **Negative-tested**: disabling the teardown gives `7 -> 8 -> 8 -> 8` and fails three checks. The assertion is the *re-claim*, not the release — a release that leaked the vector returns success just as loudly. Step 6, delegation, stays blocked on RFC 0012 as the RFC requires. |
| M6-10 | RFC 0012 step 1: the IOMMU is found, and the warning stops being a constant | ✅ `DONE` | `DMAR` parsed as untrusted firmware input, with a **seeded mutation harness** — the fuzz target the RFC adds, and the one whose failure mode is worst, because what is built from a believed table is a register window written to as if it were an IOMMU. A structure length of zero is refused rather than looped on; a register base that is zero or unaligned is dropped, not recorded. No translation is enabled: every device still reaches all of memory, and the line says so. **Negative-tested**: a parser that records no unit fails the new gate. `boot-test.sh iommu` runs QEMU with `-device intel-iommu,intremap=on`, without which the discovery path is unreachable. |
| M6-11 | RFC 0012 step 2: the translation structures, built and not enabled | ✅ `DONE` | `arch::vtd` is the VT-d encodings as arithmetic — root, context and second-level entries, address widths, index maths — pure, and proved against the specification's own numbers by 10 host tests on a machine with no IOMMU. `DevAddr` is a type the compiler keeps apart from `PhysAddr`, with an allocator tested for exhaustion, reuse after unmap and the below-4-GiB constraint a 32-bit device needs. On real hardware the window is built for the block device and **left empty**: default deny, nothing programmed. **Negative-tested**: a corrupted context index fails the gate — after the first version of that check failed to catch it, see below. |
| M6-12 | RFC 0012 step 3: translation enabled, and a device that can no longer reach the kernel | ✅ `DONE` | Identity-map what must keep working, map the firmware-reserved regions after checking each against the kernel's own image, then enable — the order is the RFC's and is not a preference, because translation has no partial state. `virtio-blk` keeps working with **zero faults**, and the boot line says whether the device is *subject to* translation as well as whether translation is on. **Negative-tested**: unmap the driver's five frames and the disk disappears, failing four gates. The `RMRR`-overlaps-the-kernel refusal has four host tests, because QEMU declares no reserved regions and the path is otherwise unreachable. |
| M6-13 | RFC 0012 step 4: `MAP`/`UNMAP`, `DevAddr`, and a refusal that names the device | ✅ `DONE` | The unit comes up **before** the device: a window names the device it translates for, and translation must be on before `DRIVER_OK` lets a device read a ring. The driver's frames are mapped as they are allocated and it is handed `DevAddr`s — its memory sits at `0xf8aa000+` and the device is told `0x100000000+`. `UNMAP` invalidates before returning, because until it does the hardware still reaches a page the caller has been told is gone. Fault records are read, so a refusal names the device, the address and the direction. **Negative test**: hand the device an address nobody mapped — `00:03.0 was refused 0x7ffffff000 (write), reason 0x05`. |
| M6-14 | RFC 0012 step 5: a `Memory` object a device can reach, and a revoke that reaches the device | ✅ `DONE` | RFC 0009's object mapped into the device window — the same frames a domain shares with another domain are what a device is given, through the same object and the same revocation. `revoke` now walks the device mapping too, invalidating the IOTLB per entry. **The assertion is asked of the device**: it reads into the object successfully, the object is revoked, and the same device at the same address is refused. A new `DmaWindow` lock rank sits inside `shared::ARENA`, and the unit's registers are cached at bring-up because mapping MMIO reaches the heap — the outermost lock — while invalidation happens under the innermost. |
| M6-15 | RFC 0012 step 6: interrupt remapping, and it works | ✅ `DONE` (2026-08-11) | The table, entries that validate **which device** may present a handle — the only thing that answers "who sent this", which is why RFC 0011 left the risk open — remappable I/O APIC lines and MSI messages, and compatibility format blocked. Held at `PARTIAL` for six days by an undelivered MSI that **was never an interrupt fault**: enabling remapping cleared translation-enable through a zeroed shadow of a write-only `GCMD`, so the device's DMA was untranslated and its address space had no remapping region in it. `Unit::adopt` fixes it, and the whole boot test passes with `iommu=remap-irq` — the block driver woken by its own device, one interrupt per request, every message a handle this kernel issued. **On by default from 2026-08-11**, which is a decision taken separately from the fix: without remapping a device can raise any vector on any CPU by writing a word, and RFC 0011 accepted that only because there was no unit to close it. What the default costs is said in the code beside it — few boots, one emulator, no physical hardware — and `iommu=no-remap-irq` is the way out for a machine where it goes wrong. A unit that cannot or will not remap is **not** a boot failure: the reason prints in red and the machine runs with the old risk. The gate is now the strong one — it asserts interrupts *are* remapped, where before it asserted only that the machine said which world it was in. |
| M6-16 | RFC 0012 step 7: a `DmaWindow` a domain holds | ✅ `DONE` | `ObjectKind::DmaWindow` with `MAP`/`UNMAP`/`INFO`, resolved under the capability arena and performed after it is released — mapping allocates, and allocating takes the heap. **Both** capabilities are checked and the device gets the weaker of their rights, so a read-only share cannot become writable by being handed to a device. **The assertion is the refusal**: a domain holding the memory and *not* the window is denied. Four real bugs fell out — see the changelog. |
| M6-17 | RFC 0011 step 6: an `IrqHandler` a domain holds | ✅ `DONE` | `BIND`, `ACK`, `RELEASE` — and **never** the MSI-X table, because an MSI is a memory write of an arbitrary vector to an arbitrary CPU and a holder that could program one would hold interrupt injection. Three refusals carry the meaning: a legacy line may not be delegated (it is shared, and a holder that never acknowledges masks a line others need), a `Notification` capability is not authority over an interrupt, and **the RFC's own precondition is enforced in code** — `irq::name` refuses when nothing is translating, because a domain driving a device needs that device's DMA constrained first. **Negative-tested**: removing the object-kind check turns the gate red. |
| M6-18 | RFC 0009 step 6: the filesystem service's bulk path | ✅ `DONE` | `fs::READ_INTO` fills a shared region in **one** round trip where the message path needs fifteen for the same file — the RFC's own comparison, measured on the data path alone, because opening a file costs the same either way and folding that in would flatter it. The caller names a **slot in its own CSpace**, never an object identity: an identity is a caller asserting what it may reach. The register path stays for short transfers. **Negative-tested** at the third attempt — see the changelog for why the first two proved nothing. |

### Honest notes on M6 so far

- **Tests that waited a fixed time have been changed to wait for completion.** A window tuned on an
  idle machine is a failed test on a loaded one, and this project's tests run under an interpreting
  emulator on a shared host where cross-CPU work has varied seventy-fold between runs. The bound is
  still there — a test that waits for ever reports nothing — but it is now an upper limit rather
  than the measurement.

- ~~**The fuzz requirement is met by a weaker mechanism than §8 intends.**~~ **Closed 2026-08-10, for
  all three parsers §8 names.** `elf::parse`, the `ustar` reader and `DMAR` each have a libFuzzer
  target in `fuzz/`. The paragraph's own argument is what the numbers went on to show: coverage
  guidance found **2,054 inputs reaching new paths** in `elf::parse` in two hours, where **twelve
  billion blind mutations** over three hours found nothing the harness had not already seen. `DMAR`
  cost more than that to reach at all — its whole-table checksum hid **a quarter of the parser** from
  a fuzzer that did not repair it, and doubling the budget bought back none of it. Blind exploration
  saturates; guidance does not; and a checksum saturates guidance too, unless the target climbs it.
  **The mechanism is now the one §8 asks for. The duration is not** — M6's criterion says 24 hours,
  and the longest campaign yet run is two.
- **A `ustar` member with a `prefix` field is reported under its short name.** Joining the two needs
  a buffer and this parser does not allocate. The build never produces one, so it is wrong in a way
  that cannot currently happen — but it is wrong, and silently.
- **The initrd is read-only, and so is the filesystem over it.** Nothing creates, truncates or
  appends. Every lookup is still a linear scan of the whole archive, and a listing is a scan per
  call.

- **The soak harness and the suite are different machines, and neither sees both.** The IPC
  rendezvous stall needed *real parallelism* — 14 failures in 40 on a two-socket host, never once
  locally. The single-processor boot hang needed *one* CPU — 7 in 24 there, 0 in 100 under the
  four-CPU soak written to catch exactly that class. Before trusting a green run, ask which machine
  it was green on.

- ~~**Two open faults are recorded rather than closed**, both in RFC 0012: the block device's MSI is
  not delivered under interrupt remapping, and a reused device address keeps its translation.~~
  **Both closed on 2026-08-11**, and they were not the same kind of thing. The MSI was never an
  interrupt fault at all — enabling remapping cleared translation-enable through a zeroed shadow of
  a write-only register, and every symptom chased for six days was downstream of that. The reused
  address was exactly what it said it was, and what was missing was a test that could tell the fixed
  state from the broken one. **What survived is the practice**: each had what was known and what was
  ruled out written beside it, and both ruled-out lists were what made the last day short. An "open"
  line in this file is an instruction to go looking, so it is only worth writing when there is
  something to find — a lesson from recording a *normal* condition as an anomaly earlier in the same
  session, and re-learned on the last day by recording a **harness** error as a machine fault.

- **Two bugs this milestone were invisible to the harness that was supposed to catch them, in
  opposite directions.** The IPC rendezvous stall needed *real parallelism* — 14 failures in 40 on a
  two-socket host, and not one in any local run ever. The single-processor boot hang needed *one
  CPU* — 7 in 24 there, and 0 in 100 under the four-CPU soak that was written to find exactly this
  kind of fault. Neither harness can see both, because they are not the same machine: oversubscribing
  a host serialises the guest's CPUs, and a second CPU keeps a machine alive that one CPU would let
  die. A green suite says less than its wording suggests, and `fault-test` — the only
  single-processor stage — was passing at roughly one run in eight for weeks.

- **`vfs::open` takes no capability.** `docs/security.md` §2 says authority must be held rather than
  ambient, and this is a place where it is not: anything that can reach the module can read the
  whole ramdisk. The kernel is the only caller today. Before a domain reaches it, an open must take
  a capability — recorded here rather than in a comment nobody reads.

- **A uniform-random mutation harness could not find the bug it was written to find.** Reintroducing
  a wrapping bounds check in the ELF parser survived half a million random mutations, because an
  offset has to land within sixteen of `u64::MAX` to wrap one — a draw of about one in 2^60. Half
  the field mutations now come from a list of adversarial constants, and the same bug is found at
  seed 424. The general lesson is stronger than the fix: a harness that only samples uniformly
  tests the middle of the space and reports confidence about the edges.

- **The ELF loader refuses two segments that share a page.** A real linker pads, so it never
  happens; but the refusal is there because merging would mean choosing one of two permission sets,
  and every choice is weaker than one segment asked for or stronger than the other did. A file
  produced by a linker Bhaskix does not control could hit this and be rejected for a reason its
  author will find surprising.

- **The frame-leak gate could report a leak that had not happened, and did.** `available_frames()`
  read the allocator's free count and the per-CPU reserves as two separate operations, while
  `frames::refill` moved frames between exactly those two places in two separate steps. A frame in
  between belonged to neither, and sixteen move per refill — so the composite read could be wrong by
  a whole reserve in either direction. It showed up once in about eight boots as a phantom
  sixteen-frame *gain*. Both sides are now single operations under one hold of the allocator lock.
  This mattered more than its size: the frame-leak check is the gate this project trusts most, and a
  gate that is occasionally wrong is worse than one that is absent, because it is believed.

- **The block driver waits by spinning.** A request is submitted and the used ring polled until it
  moves or two seconds pass. Interrupt-driven completion needs MSI-X — which is the right answer and
  avoids the other problem entirely: routing a device's legacy interrupt needs the ACPI `_PRT`,
  which is AML, which needs an interpreter this kernel does not have and should think hard about
  before acquiring. Under an emulator a read completes in tens of microseconds, so the spin is
  short; on real hardware with a real disk it would be a CPU held for milliseconds.

- **One request at a time, and reads only.** The ring holds eight descriptors and the driver uses
  three of them, once. Writes are the same descriptor chain with a different request type and no
  filesystem that would use them. Both are shapes to grow into rather than limitations that were
  discovered.

- **The whole filesystem image is read into memory at boot.** `root=disk` reads up to four megabytes
  into the heap and mounts that. A real filesystem reads blocks as it needs them; this one is an
  image held in memory, and the bound exists so that a device reporting an implausible capacity is a
  refusal rather than an allocation of whatever it claimed.

- **`pci::enable` cannot be shown to matter on the machines this is tested on.** Firmware has
  already set memory access and bus mastering, so removing the call changes nothing — the negative
  test for it passes, which is the honest result rather than a green tick. The self-test asserts the
  *state* instead, which is the actual requirement; it just cannot say whose write produced it.

- **There is no IOMMU, so a wrong descriptor address is a device writing anywhere.** Every address
  in a virtqueue is physical and the device dereferences it without asking. That is the one
  operation in this kernel no page table can contain, and the reason every buffer here comes from
  the frame allocator rather than from a pointer that happened to be at hand.

  [memory.md](docs/memory.md) §5 commits the project to *printing* this degraded threat model rather
  than silently accepting it, and until RFC 0009 was written the driver did not. It does now, and a
  boot gate asserts the line — so the day a DMA-capable device is brought up without that warning is
  a red build rather than a document that quietly became untrue.

- **The user-mode shell moves sixteen bytes per round trip.** A message is four registers
  ([RFC 0008](docs/rfc/0008-syscall-and-ipc-shape.md)); two of them carry bytes. Printing a line of
  help is therefore a few dozen context switches. The alternative is shared memory, which needs a
  page granted across a domain boundary and a capability type to describe it — an RFC's worth of
  decisions this milestone does not need. What the slow version buys is worth keeping in mind when
  the fast one arrives: **no pointer crosses the boundary**, so the kernel never dereferences an
  address a caller chose, and the whole class of confused-deputy bugs that `copy_from_user` exists
  to contain cannot occur.

- **`Recv` still returns a truncated message.** `Call` was fixed at M6-05 to return all four
  registers; `Recv` still overwrites two of them with the caller identifier and the badge, because
  nothing in the tree receives from ring 3 yet — the services are kernel threads using `ipc::recv`
  directly. The first user-mode service will need this fixed, and will find out by receiving
  nonsense in `args[1]`.

- **A service cannot tell that a caller has died.** The filesystem service releases a session when
  the caller says `RESET`, and has no other signal. A program that stops without one holds a slot
  until the machine restarts, and with two slots that matters. The fix needs a mechanism that does
  not exist: an endpoint that reports when the capability reaching it is revoked. Found the hard
  way — the boot self-test's two test callers held both slots for the rest of the machine's life,
  and the shell was refused before it started.

- **Each service is one thread, so it answers one caller at a time.** While the console service is
  blocked waiting for someone to type, it is not answering writes. That is correct with one shell
  and would deadlock two.

- **The kernel shell is the kernel.** It runs in ring 0, calls kernel functions directly, and holds
  no capability, so it is an operator's tool and not a security boundary. Every command is read-only
  on purpose: a debugging shell that can write memory makes every session with it afterwards
  suspect. M6-05's user-mode shell is the one that has to ask.

- **A terminal escape sequence loses its first byte and keeps the rest.** The line editor drops
  `0x1b` and then inserts `[A` as ordinary characters, so an arrow key types two letters. Correct
  handling needs a state machine over escape sequences, which is a parser, and this is not the
  milestone to add one — but the current behaviour is wrong rather than merely absent.

- **One I/O APIC, and the first one.** A machine with several routes high global interrupt numbers
  to the others, and nothing here does that. The count is reported so a machine where it matters is
  visible rather than silently half-served. Sixteen interrupt source overrides are read; a table
  with more says so.

- **A latent one-CPU deadlock was found and closed.** `time::on_tick` woke expired sleepers with a
  *blocking* runqueue lock, from an interrupt handler that may have interrupted a thread holding
  that very lock. The window is a few instructions wide and a timer has to expire inside it, so it
  had never been hit — but it was reachable, and it would have hung the machine with no output.
  Interrupt-context wakes now use `try_lock` and record what they could not deliver for the next
  tick.

- **The loader does no relocation, so nothing dynamic loads.** `ET_DYN` — which is what a PIE is —
  is refused outright, which is also what keeps a dynamic loader's attack surface out of the
  kernel. Position-independent user programs need a decision recorded in an RFC before they need
  code.

### M5 — Domains, capabilities, syscalls, user mode

| ID | Task | Status | Notes |
|---|---|---|---|
| M5-00 | Decide the syscall and IPC shape | ✅ `DONE` | [RFC 0008](docs/rfc/0008-syscall-and-ipc-shape.md) **accepted 2026-08-04**, answering **A2**, **A3** and **A4**. Thirteen milestones were built against it first; the code needed no change on acceptance, which is the outcome the alternative — waiting — would also have produced, more slowly and with less evidence. |
| M5-01 | Capability objects, CSpace, derive/revoke | ✅ `DONE` | All four rules of `docs/security.md` §2 enforced and **each negative-tested**. Derivation monotonicity tested over every one of 64×64 rights pairs, not sampled. |
| M5-02 | `Domain` with `ResourceEnvelope` | ✅ `DONE` | Envelope refuses at allocation time (T10); CPU share **divided** among a domain's threads so it does not grow with thread count; destruction revokes the domain's whole derived subtree. **Negative-tested** in both directions. |
| M5-03 | `SYSCALL`/`SYSRET` entry, dispatch, SMAP bracketing | ✅ `DONE` | Exercised for real as of M5-04: ten system calls from ring 3 per boot. Built on RFC 0008's recommendation; **accepted 2026-08-04** with no change to this code. |
| M5-04 | Ring 3 execution | ✅ `DONE` | A program runs in ring 3, enters the kernel through `SYSCALL`, and is interrupted there. **Negative-tested**: removing the interrupt-entry `swapgs` or leaving `RSP0` zero both fail the gate. |
| M5-05 | Synchronous IPC: endpoints, `Call`/`Reply`/`Recv`, badges | ✅ `DONE` | Rendezvous, no buffering. Exercised through the whole syscall path — domain, CSpace, capability, type check, badge. **Negative-tested**: taking the badge from the caller's frame makes the service unable to tell its clients apart. |
| M5-05b | IPC from ring 3 | ✅ `DONE` | A user program calls a service by capability, blocks, is woken across CPUs, and receives the reply — proved by sending the value back. **Negative-tested**: with no capability, or no domain, the syscalls still happen and reach nothing. |
| M5-06 | Per-domain capability quotas | ✅ `DONE` | Charged on every capability a domain gains and released on every one it loses, attributed by owner so a revocation spanning domains returns quota to each. **Negative-tested**: a quota of zero stops ring 3 deriving. |
| M5-07 | Grant, derive and revoke from user mode | ✅ `DONE` | `Invoke` methods, not new syscall kinds — RFC 0008 fixes the set at six. Ring 3 derives a badged capability, calls through it, revokes the parent, and the next call fails. |

### Honest notes on M5 so far

- **M5 is marked `COMPLETE` and one of its exit criteria has never been true.**
  [roadmap.md](docs/roadmap.md) M5 reads *"a user-mode program runs, invokes capabilities, is denied
  what it does not hold, and **is killed cleanly when it faults**."* The first three clauses are
  gated. The fourth is false: a fault in ring 3 calls `halt_forever` and stops the machine.
  Demonstrated on 2026-08-07 by adding a temporary `crashme` to the user-mode shell — a null write
  from ring 3 took down the console and filesystem services, which had done nothing wrong.
  It was never caught because **no test in this project has ever faulted from ring 3**: all six
  faults in `tests/qemu/fault-test.sh` are injected from kernel mode. Closed by
  [RFC 0017](docs/rfc/0017-process-management.md) step 1; recorded here rather than quietly fixed,
  because a milestone marked complete on an untested criterion is the exact failure this file exists
  to prevent.

- **`try_lock` on a query is a wrong answer, not a delayed one — three times now.** A read that
  answers "no such thread" for a thread on a busy CPU is indistinguishable from one that does not
  exist. It has caused an intermittent failure in `set_domain_weight`, in `start_all` and in
  `weight_of`/`cycles_of`. `try_lock` belongs where *failing* is a valid outcome — interrupt context,
  and the switch path — and nowhere else.
- **`GRANT` between domains is implemented and unexercised.** Ring 3 derives and revokes for
  itself, which the gate proves. Handing a capability to *another* domain needs a second domain and
  a capability naming it, and no test builds that arrangement — so the cross-domain half of
  delegation is code written and reviewed rather than demonstrated. It is the same status M5-03 had
  before ring 3 existed, and deserves the same treatment.
- **The quota counts arena nodes, not CSpace slots.** A capability that has been revoked but whose
  slot is still installed is not charged, because the node is gone; the dead slot still occupies one
  of the domain's 64. Both are bounded, and they are bounded separately.
- **A lost wakeup lived in the IPC path for two milestones.** `call` and `recv` checked the mailbox
  and *then* marked themselves blocked, so a message delivered in between woke a thread that was not
  blocked yet — and it slept with its answer already in hand. Fixed by marking first and checking
  second, the same shape M4-09's wait queue got by fusing the two steps under one lock. It surfaced
  only under heavy host load, which is why two milestones of green runs did not find it.
- **IPC has no timeout on `Recv`**, so a service bug hangs its callers indefinitely. RFC 0008
  records it as unresolved because it needs a policy decision rather than code.
- **"No message is ever lost" is not gated.** The IPC test asserts that every reply that arrived was
  correct and that progress was made; it cannot distinguish a lost message from a slow machine
  inside a boot-length window. Throughput varied seventy-fold between runs on this host, which is
  why the count is reported and not asserted.
- **`RSP0` and the syscall stack are now per-thread**, installed on every context switch, which is
  what a blocking system call requires. Fixed as the first step of M5-05.
- **A faulting user thread is not contained, it is fatal.** ✅ **Fixed 2026-08-07**, by
  [RFC 0017](docs/rfc/0017-process-management.md) step 1. This note stood from M5 and was right
  about the substance and imprecise about the cost: `halt_forever` halts *the CPU it runs on*, not
  the machine, so a ring 3 fault took a processor permanently — with interrupts disabled, so no
  timer and no IPI could ever wake it — and leaked the domain, its envelope and its thread. On one
  CPU that is the machine; on four it is a quarter of them per faulting program. It survived because
  "the probe never faults" stayed true for four milestones: **no test here had ever faulted from
  ring 3.** Now `bhaskix.fault=user` does, and the assertion is what prints *afterwards*.
- **There is no `swapgs` protection against an NMI.** The interrupt path decides whether to swap by
  looking at the interrupted `CS`, which is wrong for an NMI arriving inside the syscall stub's
  first instruction — kernel `CS`, user `GS`. Nothing enables an NMI source, so the window is
  unreachable rather than merely unlikely, and `arch/x86_64/src/trap.rs` names the standard fix.
- **`bhaskix-kernel` is at 459 of a 460 `unsafe` budget.** The next line will fail the gate, which is
  the gate working; it needs a raise with a reason at that point, not before.
- **Domain CPU share is an approximation of the two-level runqueue, not a replacement.** Dividing a
  domain's share among its threads gets the *aggregate* right — which is the property
  `docs/scheduler.md` §3 claims and the one a per-thread weight silently breaks — and gets the
  distribution *within* a domain wrong: every thread in a domain is weighted equally, so a domain
  cannot prioritise among its own threads. That needs the real two-level structure.
- **A domain's threads are counted, not owned.** Destroying a domain releases its accounting and
  revokes its authority, and does not stop its threads. A thread outliving its domain holds no
  capabilities, which contains it, but it still runs and still consumes CPU.
- **The capability quota is declared and not charged.** `max_capabilities` is enforced by
  `Domain::charge_capability`, which nothing calls, because a domain has no way to derive anything
  until there are syscalls. Until M5-03 the arena remains a fixed global resource with no per-domain
  bound — T10 through a door that is currently closed for a different reason.
- **A domain records no address space.** The structure `docs/architecture.md` §4 specifies has one;
  this does not, because binding one needs the object table that M5-02 only begins.
- **Capabilities name objects that do not exist.** `ObjectRef` carries a kind and an identity, and
  nothing maps an identity to a frame, a thread or an endpoint yet. The authority mechanism is real;
  the things it authorises are not, and until M5-02 the self-test authorises a number.
- **Revocation is `O(arena × depth)`, by choice.** A sweep to fixed point rather than child pointers:
  child links make revocation `O(subtree)` but require insertion to maintain a second invariant that
  must be exactly right, and a missed branch is a privilege-escalation bug. The sweep is obviously
  complete. Revisit if a workload revokes hot.
- **No per-domain quota.** `MAX_CAPABILITIES` is global, so a domain that derives in a loop denies
  service to every other domain. This belongs in `ResourceEnvelope` and is M5-06.
- **The badge is unreadable by its holder because no function returns it to them** — which is the
  right enforcement today and becomes a real access-control decision once syscalls exist.

### Bugs found and fixed during M4

1. **New threads started with interrupts disabled, and the machine simply stopped.** A thread that
   has run before resumes through `iretq`, which restores `RFLAGS` and with it the interrupt flag.
   A brand-new thread has no such frame — it is entered by a `ret` from inside the timer's interrupt
   gate, which cleared `IF` on entry. So the first thread scheduled ran with interrupts off forever,
   the timer never fired again, and there was no crash to look at: no exception, no triple fault,
   just a halt. Diagnosed from QEMU's interrupt trace ending at a timer vector with nothing after.
   Fixed with an `sti` in the thread trampoline.
2. **Loading the GDT silently wiped the per-CPU `GS` base.** Secondaries set their `GS` base and
   *then* built their descriptor tables — but loading any selector into `GS`, including the null
   selector a GDT reload writes, resets the base to zero. Every later `gs:`-relative read therefore
   dereferenced address zero, and it surfaced as three page faults at `CR2 = 0` deep inside
   unrelated code, plus two "address space lock held" reports from a fault handler that could not
   service them. Found by resolving the faulting RIP through the KASLR slide back to a symbol and
   disassembling it: the faulting instruction was `mov %gs:0x0,%rcx`, and the GDT load sat between
   it and the `wrmsr` that was supposed to have made it valid. Fixed by splitting per-CPU setup into
   `install` (claim the identity, which the GDT build needs) and `activate` (point `GS` at it), so
   the two halves *bracket* the GDT load instead of preceding it. Negative-tested: putting
   `activate` back before the load reproduces all three faults.
3. **My own trampoline design was internally inconsistent** — it expected the entry point in `rax`,
   which the context switch does not restore. Caught while writing it; entry point and argument now
   travel in `r12` and `rbx`, which are callee-saved and therefore actually preserved.

### Honest notes on what is *not* proven

- **Balancing is pull-only, topology-blind and uncharged.** A CPU steals when it would otherwise
  run only the thread already on it; nothing pushes work, nothing runs periodically, and there is
  no ACPI topology, so a steal is as likely to cross a socket as to stay on one. Migration cost is
  not measured, so `docs/scheduler.md` §5's rule that a move must pay for itself is not enforced —
  the only brake is the imbalance threshold.
- **Convergence rests on one constant.** `STEAL_IMBALANCE = 2` is what stops a thread migrating
  back and forth forever. It is unit-tested and argued for in `docs/scheduler.md` §5, but it has
  never been tested against a workload that changes shape while it runs.
- **Shootdown is one address per IPI round trip, and one shootdown at a time.** Tearing down a range
  costs a round trip per page, which is the wrong shape for address-space teardown; batching is the
  obvious next step and deliberately untaken until there is a workload to measure. Teardown avoids
  the cost entirely today by skipping shootdown for address spaces no CPU has loaded.
- **`is_active` checks only this CPU's `CR3`.** Sufficient because secondaries never load an address
  space, and wrong the moment they do — it must become a per-space "loaded on" mask.
- **The locking is barely contended.** Each runqueue lock is taken by exactly one CPU plus its own
  timer interrupt, which is by design — but it means the only genuinely multi-CPU lock traffic is
  the console and the shootdown path. Nothing has stress-tested any of it.

- **This is round-robin, not the scheduler `docs/scheduler.md` specifies.** No priorities, no
  fairness weighting, no virtual deadlines, no RT class, no admission control. The fairness figure
  printed at boot is reported rather than asserted, because a tight bound on round-robin would be
  measuring timer jitter rather than any property worth defending.
- **Lock ranking does not stop a thread being preempted while holding a spinlock.** It makes the
  *order* safe; it does not make holding a spinlock across a context switch safe. A thread
  preempted while holding the heap leaves every other thread spinning for it until it is scheduled
  again — progress, but by luck of the timer rather than by design. Linux disables preemption
  inside `spin_lock` for exactly this reason and Bhaskix does not, which is a real gap that ranking
  made visible without addressing.
- **The `switching` handshake has not been observed doing its job.** It is the rule that stops a
  thief taking a thread whose registers are not yet saved, and it is the one hazard here that
  corrupts state rather than merely stranding it. Removing it fails a unit test, which proves the
  policy encodes the rule — not that the race it guards against was ever reached.
- **Real-time wakeup latency is 120–500 µs against a 50 µs budget.** Measured and printed at every
  boot rather than omitted. Part of the gap is that this is QEMU's TCG interpreter on a shared build
  machine and not a latency measurement of anything real; part is the missing reschedule IPI. It is
  a regression baseline, not a claim to have met `docs/scheduler.md` §4.
- **Priority inheritance does not exist**, which by §4's own words makes the RT latency bound a lie
  under contention. It needs a lock with an owner that can sleep; the spinlocks here have neither.
- **Fairness is between threads, not domains.** A domain that spawns more threads gets more CPU,
  which is exactly what §3's two-level runqueue exists to prevent. It needs domains, so M5.
- **The frame reserve is not a memory guarantee.** A CPU that exhausts its reserve between refills
  refuses the fault exactly as before; the reserve makes that rare, not impossible. Sizing it
  against a real fault rate needs a workload that produces one, and there is none yet — the boot
  report counts misses so the gap is visible rather than assumed.
- **A frame dropped by `give` when both the reserve and the allocator are unavailable is leaked.**
  Deliberate: the alternative is a fault handler that waits for a lock. It has not been observed,
  and nothing counts it.
- **Tick counting is no longer a measure of time**, and anything written against it is wrong. The
  self-tests were converted to a wall clock; nothing else in the kernel measured duration in ticks,
  but the next thing that wants to must not.
- **A cross-CPU wake is not prompt.** It marks the thread `Ready` and stops; nothing interrupts the
  target CPU, so the woken thread waits for its next timer tick — up to 10 ms at 100 Hz, against
  `docs/scheduler.md` §4's 50 µs target. This is why the ring self-test measures dozens of laps per
  second rather than thousands. The fix is a reschedule IPI, using the mechanism shootdown already
  has.
- **One safety property is structural because it could not be tested.** Enqueueing a waiter and
  marking it blocked must happen together; separating them is a real lost-wakeup bug, and it was
  written deliberately and the ring test *did not catch it* — the window is a few instructions and
  116 sleeps never landed in it. The two steps are now fused in one function rather than left
  adjacent under a shared lock. The gate still cannot see that class of bug; the code makes it
  unwritable instead.
- **Excluding `Blocked` from scheduling is not covered by a gate.** Making blocked threads
  schedulable again still passes the ring test at 61 laps: they get scheduled, immediately re-block,
  and the ring works while burning CPU. It is a sleep-actually-saves-CPU property, and the boot test
  has no way to measure idle time.
- **Thread capacity is fixed at 8 per CPU** and stacks are never reclaimed. `exit` marks a thread finished
  but its stack stays mapped, so thread creation is effectively one-way.
- **No lock ranking**, which `docs/coding-style.md` §7 requires and which becomes load-bearing the
  moment there are enough locks to order.

### Open defects

| Defect | Evidence | Owner |
|---|---|---|
| **The shell gives up on transient congestion.** `Status::Congested` (8) means the endpoint queue was full at that instant — recoverable. `serve()` now retries it and the queue-entry leak that made it permanent is fixed, but the shell's `ls` and `cat` still print `refused, status 8` and stop, and `write()` still drops output silently and says so in a comment. | Seen 2026-08-08 in 2 of 72 soak runs, once the shell stopped discarding the status. A later 10-run `soak-shell` the same day was clean, which at a rate near 3% is the expected outcome and says nothing either way. **A 50-run soak on an idle host (2026-08-09, ~97% idle, slowest run 20s) was also clean, and that one could have spoken**: at 3% it should have turned up one or two failures, and a clean fifty happens about a fifth of the time. **Then 100 runs, also clean, slowest 21s** — the "runs in the hundreds" the previous line asked for. At 3% that is about three expected failures against none observed, which happens roughly one time in twenty. **The rate is very probably below 3%; it is not shown to be zero**, and a defect seen twice cannot be closed by not seeing it. The machine was capable of failing on the same host that day, so this is not a rig that cannot fail. **The 100 runs carry a second load**: the lock release-order fix that same day changed the release path of *every* lock in the kernel, and 1000 boots exercise only bring-up — this is the one test that writes to the machine, driving console and filesystem services under sustained IPC, so it is the evidence that the change disturbed nothing under real service traffic. Reproduce with `make soak-shell SOAK_SHELL_RUNS=<n>`. | unassigned |
| ~~**A boot sometimes stalls before any service starts, at one of two points.**~~ **BOTH FIXED 2026-08-09** — see §7. The first was a lock release giving up its "this CPU holds something" bookkeeping before releasing the lock (1500 boots clean, ~11 expected). The second was never a `demand paging` fault at all: `smp::start_secondaries` read the online count *after* the loader's bring-up call, double-counting every secondary that had already registered, so the bootstrap CPU waited for seven CPUs on a four-CPU machine (600 boots clean, ~2 expected). Kept here rather than deleted, because the row's own history is the record of how long it was mislabelled. Original text follows. **A boot sometimes stalls before any service starts, at one of two points.** After `syscall entry armed`, or earlier still at `demand paging`. Not the service fault fixed on 2026-08-08 — both are earlier than the console or filesystem domains exist. | Seen 2026-08-08 at roughly 1 boot in 70. The bring-up watchdog now dumps every thread and the IPC counters for the `syscall entry armed` case, and reports for every CPU how many of 20 samples found its runqueue readable — so a held runqueue is stated rather than showing up as a CPU with no threads listed. That says a runqueue is stuck, **not which CPU is at fault**: `spawn_on` and the wake paths block on a remote runqueue lock, so the holder need not be the CPU reported. **The `demand paging` case is outside its reach**: it stalls before `sched::start_all`, and a watchdog that is a thread cannot report a stall that precedes the scheduler — catching it needs a timer-interrupt or NMI mechanism that does not exist yet. **Caught, twice, on 2026-08-08**: 2 of 200 boots, one at a time on an idle host (mean 79% idle, boots otherwise a steady 16–17s), so this is the kernel and not the contention that spoiled an earlier run. **The stall has a signature now.** Both dumps are the same shape: last line `syscall entry armed`; **one CPU contributes no threads to the walk at all** and its runqueue reads `0 of 20 samples` — held continuously for two seconds, so not a thread waiting for a wake, which would leave the lock free. Both were caught by the watchdog firing on its own deadline rather than a shortened one. **It is not IPC**: `dropped`, `wake_missed` and lost deferred wakes were all zero in both. **It is not a fixed CPU**: cpu 1 in one, cpu 0 in the other — and the holder need not be the CPU named, since `spawn_on` and the wake paths block on a remote runqueue lock. **Since 2026-08-09 the lock records its taker**, and the first two captures under it (300 boots, 2 failures) both name **cpu 2 holding cpu 0's runqueue while cpu 2 itself reads healthy** — so the CPU that goes silent is the victim, not the culprit. Running total **4 stalls in 500 boots, about 1 in 125.** The mechanism is narrowed to the only two paths that take a remote runqueue lock, `wake_with` and `try_steal`, and to one unproven asymmetry: a lock taken by `try_lock` does not join the held set, so its holder is invisible to the check in `preempt` that keeps lock holders on their CPU. See §7. The two dumps below predate the owner field and do not name a holder. One dump is reproduced in full in §7 under the 2026-08-08 entry that caught it. **Running total: 7 stalls in 1000 boots, about 1 in 140.** One hypothesis — a `try_lock` holder descheduled mid-`exit` while holding a remote runqueue — was instrumented, appeared confirmed on one sample, and was **refuted** by a 500-boot run at the same rate with the guard in place (§7, 2026-08-09). **The live lead is now a different signature**: a runqueue held for all 20 samples while recording *no owner*, which suggests `locked` left set rather than a holder descheduled. A third failure stalled at `demand paging`, out of the watchdog's reach as always. **RESOLVED for the `syscall entry armed` case, 2026-08-09.** The lead above was right about *where* and wrong about *why*: nothing was descheduled holding a lock. A release gave up its "this CPU holds something" bookkeeping **before** it released the lock, so a tick in that window carried the holder away with `locked` still set and the owner already cleared — which is exactly why the dump said *held by nobody*. Fixed by splitting the two questions the rank mask was answering; see §7, 2026-08-09. **1000 boots with no stall, where about seven were expected.** **The second stall is not in demand paging at all, and this file has been mislabelling it.** A 500-boot run on 2026-08-09 failed twice, both the same way, and both logs end with `demand paging faults serviced from the region map; copy-on-write copies` — **a complete line, terminated, identical to a healthy boot's.** The stage that never prints is the *next* one, `cpus N online of N reported`, from `smp::report`. So the hang is in **secondary-CPU bring-up**, between those two lines, and calling it the demand-paging stall sent the reader to the wrong subsystem. **Rate: 3 in roughly 1000 boots, about 1 in 330** — now the dominant failure mode, since the one above is fixed. No watchdog dump in any of them, exactly as predicted: this precedes `sched::start_all`, and a watchdog that is a thread cannot report a stall that happens before the scheduler exists. **One hypothesis, untested:** `smp::start_secondaries` waits on `while percpu::online_count() < expected && spins < 2_000_000_000`, which is bounded but by a *spin count* rather than a deadline — two billion `pause` instructions may well exceed the soak's 120-second cap, in which case this is a slow path being counted as a hang, and the fix is a real deadline plus a report naming which CPU never arrived. Reproduce with `make soak-boot SOAK_RUNS=500 SOAK_JOBS=2` on an idle machine, keeping `SOAK_LOG_DIR` — and note the harness keeps per-boot logs only when a run *fails*. | unassigned |

### Blockers

| Task | Blocked on | Owner |
|---|---|---|
| M1-17 | Physical UEFI machine with serial. QEMU cannot substitute. | Tarun Kumar Kushwaha |
| Repo metadata | GitHub description and topics are unset, and `main` has no branch protection — `GOVERNANCE.md` §2 requires review for non-trivial changes and nothing enforces it. Deploy keys have no API scope, so these need the web UI. | Tarun Kumar Kushwaha |
| CI log access | Reading Actions logs needs authentication; unauthenticated API gives 60 requests/hour and only pass/fail. A fine-grained token with `Actions: read` would remove both limits. | Tarun Kumar Kushwaha |

## 4. Upcoming work

Scope is in [docs/roadmap.md](docs/roadmap.md). This table listed M2 to M6 as `TODO` long after all
five were finished — it was written when they were ahead and never revisited, which is what a
table nobody has a reason to read becomes. It is Phase 2's remaining bullets now, because those are
what is actually ahead.

| Phase 2 bullet | Status | Notes |
|---|---|---|
| Shared memory and notifications | ✅ done | RFC 0009 and RFC 0010, M6-13 … M6-18 |
| Service framework | ✅ done | RFC 0013, M7 above |
| IOMMU: discovery, per-device domains, strict mapping | ✅ done | RFC 0012, all seven steps; per-device windows landed with M7-13. Interrupt remapping **works** as of 2026-08-11 (M6-15) and is still off by default — not for a defect, but because the path was silently broken for its whole life, has been seen working on one emulator, and has never run on real hardware |
| Driver framework — PCIe/ECAM, `register_block!`, `Mmio<T>`, mock-MMIO harness | ✅ **done** — RFC 0014, M8 above | `bin/blkd` is a driver in a domain written by hand, and it cost three bugs the kernel's driver had already learned. The RFC's case is that invoice. It also asks something port I/O could not: with ECAM a function's configuration space is a *page*, so how much of it may a domain hold? BARs say not all of it |
| Full VFS — mount points, writable filesystem, journal, page cache | ✅ **done** — RFC 0015's six steps and RFC 0016's five, M9-01 … M9-17 | Three things, not one, and all three landed. The **ambient root is gone**: a directory is a badged endpoint capability to `bin/fsd`, `kernel/src/namespace.rs` is deleted, and there is no way up out of a directory. The journal's claim is tested by interrupting the machine at *every* write on the host, and once on a real disk through the block service. The cache came last because the journal decides when a dirty page may go home — and it now lends a page of itself to a caller, read-only, with nothing copied. What is **not** done: mount points, which nothing has needed yet. **The fuzzing is done** (2026-08-10) — all three parsers §8 names now have libFuzzer targets: 901 million executions over `elf::parse` and 12 billion seeded mutations, 2.45 billion over `DMAR`, and 96 million over `ustar` uncapped plus 250 million capped. No crash, no hang, no unbounded loop. The duration §8 asks for is still not met: 24 hours, against two |
| Process management — capability-shaped fork/exec, process trees, reaping | ✅ **done** — RFC 0017 steps 1–6 | Nothing creates a domain except boot code — all 21 `domain::create` calls are in `kernel/src/lib.rs`, and it takes a `&'static str`, which is itself a statement that the caller is compiled in. Three more gaps the RFC found: a ring-3 fault **costs a processor permanently and leaks the domain** (M5's unmet criterion, above — ✅ closed by step 1 on 2026-08-07); `destroy` leaves a domain's threads running, which `domain.rs` documents against itself; and a caller whose service died blocks for ever, which is RFC 0013's question 1. Six steps, and **step 1 is worth doing alone** |
| Networking — virtio-net, Ethernet, IPv4/IPv6, UDP, TCP, sockets | ⬜ `TODO` | Gated on the driver framework rather than on anything network-shaped |

---

## 5. Phase 0 — complete

| Item | Status |
|---|---|
| Vision, architecture, memory, scheduler, security, driver-model, ai-native, coding-style, roadmap docs | ✅ DONE |
| Repository structure and layout doc | ✅ DONE |
| Governance, contributing, authors, RFC template | ✅ DONE |
| License decision (A1) and `LICENSE` / `NOTICE` files | ✅ DONE |
| `tools/setup-dev.sh` | ✅ DONE |
| Design-document review by two people who did not write them | ⬜ **OUTSTANDING** |

> Phase 0's review criterion is genuinely not met — the documents have one author and no independent
> reviewers. This is recorded rather than quietly marked complete. It does not block M1 code, but it
> should be closed before the architecture calcifies.

---

## 6. CI gates

A task cannot be `DONE` with any of these failing. Each becomes active at the milestone shown.

| Gate | Active from | Enforces |
|---|---|---|
| `cargo fmt --check` | M1 | coding-style.md §2 |
| `cargo clippy -D warnings` | M1 | coding-style.md §2 |
| Host unit tests | M1 | coding-style.md §8 |
| QEMU boot test | M1 | Milestone exit criteria |
| `unsafe` budget | M1 | coding-style.md §3 |
| Limine containment (only `boot/` may name it) | M1 | architecture.md §1 |
| Dependency direction / no cycles | M1 | architecture.md §5 |
| No vendor strings in published files | M1 | Project policy |
| Frame-leak test (1000 address spaces, zero drift) | M3 | memory.md §7 |
| RT latency p99.9 < 50 µs | M4 | scheduler.md §4 |
| Fuzz targets on every untrusted parser | M6 | coding-style.md §8 |
| Interactive shell test (types at the machine) | M6 | Milestone exit criteria |
| Soak: repeated boots **and repeated shell runs** (`make soak`; CI nightly, not per push) | M6 | Faults that depend on where a tick lands |
| Both service placements build | Phase 2 | architecture.md §2 |
| AI-degradation test (kill `bhaskixd-ai`, suite still passes) | Phase 4 | ai-native.md §4 |

---

## 7. Changelog

Newest first. One entry per meaningful change of project state.

### 2026-08-11, last (interrupt remapping is on by default)

A decision, taken after the fix rather than inside it. **Without remapping a device can raise any
vector on any CPU by writing a word** — RFC 0011 named that and accepted it, because at the time
there was no unit to close it. There is now, and RFC 0012 step 6's whole purpose was to retire it.

**What the default costs, stated because it is not nothing.** This path was silently broken for its
entire life until the day before it was turned on, so it has few boots behind it. It has been seen
working on one emulator. Nothing has ever booted this kernel on physical hardware, where an IOMMU is
much less forgiving than a model of one. `iommu=no-remap-irq` turns it off, and that escape hatch is
what makes turning it on reversible rather than brave. `iommu=remap-irq` is still accepted and now
means nothing, because command lines outlive the reasons they were written.

**A unit that cannot remap is not a boot failure.** The reason prints in red and the machine runs
with the old risk, in the same words the opted-out case uses — what matters to whoever reads the
line is the state the machine is in, not how it got there.

**The gate got stronger, and only could once the default changed.** It asserted that the machine
*said which world it was in*; it now asserts that interrupts *are* remapped. The weak version was
right while remapping was off and is wrong now: a machine that fell back would boot, pass every
other check here, and be a machine where a device can forge an interrupt. That is the degradation
this suite exists to refuse to ship quietly, and this is the only line that sees it.

Verified in every configuration: IOMMU with the new default, IOMMU with `iommu=no-remap-irq`, no
IOMMU at all, UEFI, the `fsd` placement, and the shell tests.

### 2026-08-11, later still (device-address reuse is on, and the proof is a test that fails when it should)

**The second RFC 0012 fault is closed, and unlike the first it was real all along.** Reuse has been
disabled since M6-13 with the reason written into `allocate`: after map → unmap-with-invalidation →
map of the same address, a device was seen still reaching the old page, unfaulted. The blocker was
never the allocator; it was that nothing proved invalidation took effect.

`iommu_reuse_self_test` is that proof, and it is built so that it cannot pass by accident:

- **Two objects, both alive**, and the *old* one is the one checked. A test that only confirmed the
  new object got its sector would pass just as happily against a stale translation — because a
  stale translation writes to the old page and says nothing.
- **Two different sectors.** If both reads fetched the same bytes, every frame would hold the right
  contents either way.
- **It refuses to claim anything when the address is not reused.** Reuse is a policy `allocate`
  decides; a green line on a bump-only allocator would be exactly the kind of check this file has
  nine of in a table above.

**Negative-tested, and it reproduces M6-13 word for word.** With the invalidation in
`unmap_device` removed:

```
iommu reuse    FAILED: first read true, unmapped true, second read false,
               old page untouched false, fault None
```

The new object's read never arrives, the **old** object's page is written through an address it no
longer owns, and **no fault is raised** — which is what "a device still reached it, and the access
was not refused" was describing. The fault was real, the diagnosis was right, and what was missing
was a way to tell the fixed state from the broken one.

With invalidation in place the same test is green, in all three configurations: no IOMMU, IOMMU, and
IOMMU with `iommu=remap-irq`.

**What changed in the allocator.** Exact-size reuse only — a partial match would leave a remainder
nobody tracks, and the window has 512 GiB, so the addresses that would recover are not worth the
bookkeeping. The host test that asserted a freed address is *never* handed out again now asserts the
size and region rules instead, and `a_freed_extent_is_reused` is no longer `#[ignore]`d. There are
now **no ignored tests** in the kernel crate.

### 2026-08-11, later (the MSI fault is closed, and it was never an interrupt fault)

**Enabling interrupt remapping turned the IOMMU off.** One register read says the whole of it:

```
gsts on entry     0xc0000000     TE=1 — translating
gsts after QIE    0x44000000     TE=0 — not translating any more
```

`GCMD` is write-only, so a `vtd::Unit` carries a shadow of what was last written to it, and
`Unit::new` starts that shadow at **zero**. `enable_interrupt_remapping` built a fresh unit around a
window that was already translating and then issued a command through it; the command wrote zeros
into every bit it was not setting, and one of those bits was translation-enable. From that moment
every device's DMA was untranslated, and the machine went on printing that interrupts were remapped.

**Everything the last six days chased was a symptom of that.**

| Symptom | Why |
|---|---|
| The device's MSI never reached the unit | With translation off, QEMU gives the device a passthrough address space, which does not include the interrupt-remapping region. The message went straight to the APIC in compatibility format |
| The I/O APIC's line worked throughout | It is not a device DMA and never went through that address space |
| The device completed requests but the driver saw nothing | Untranslated DMA wrote to the addresses as physical, so the used ring the driver was watching was never touched |
| `iommu memory`: "mapped, unfaulted, and pointing somewhere else" | Exactly what an untranslated write looks like. This was on the screen the whole time, in the same boot, and read as part of the interrupt fault |

**Fixed** by `Unit::adopt`, which seeds the shadow from `GSTS` and keeps the bits that describe a
state the unit is *in* — translation, the queue, remapping, compatibility-format blocking — while
dropping the pointer-set bits, whose status means a pointer was latched and whose command would
latch it again. `enable_interrupt_remapping` now adopts, and checks that translation survived,
because the only place that is visible is there. Pinned by a host test against a fake register
window.

**After it**, with `iommu=remap-irq`:

```
iommu memory   an object was reachable at 0x100006000, 1 mappings revoked, and the device was
               then refused it (0x100006000, reason 0x05)
virtio-blk irq msi-x vector 0xfc; 1 waits, 0 spins, 1 interrupts per request,
               0 woken by the clock rather than the device
```

Every message now arrives as a handle: 139 through handle 5 to vector 251, three through handle 1 to
vector 252, the I/O APIC's through handle 0. **RFC 0012 step 6 works**, and RFC 0011's residual risk
is retired in fact rather than in principle.

**Nothing else is wrong, and the thing that looked wrong was the harness.** The first write-up of
this fix recorded one remaining failure — `block service`, 512 bytes with the wrong contents — and
that failure was manufactured by the way it was being tested. `tests/qemu/boot-test.sh` deletes and
regenerates the domain disk before every run, at lines 174–175, because a boot *writes a filesystem
to it*; the hand-rolled QEMU invocations used to chase this fault did not. So every run after the
first read a sector 0 that the previous run had formatted, and compared it against the marker the
image is built with. Through the real harness, with remapping on: **every check passes.**

Named here rather than quietly deleted, because it is the second time in two days that a red herring
came from the measurement rather than the machine, and because the ruled-out list is only worth
having if the wrong turns are on it too. **A test harness that prepares state is part of the test.**
Reaching past it to "just run QEMU" reproduces the boot and not the test.

**The lesson, which is not about IOMMUs.** A write-only register with a shadow is a cache, and a
cache rebuilt from nothing is a cache that lies. `Unit::new` was correct exactly once — the first
time a unit is programmed — and every later use of it was writing zeros into hardware state the
kernel had set. The comment on the shadow field said "what was last written to `GCMD`, because it
cannot be read back", which described the mechanism perfectly and did not connect it to `new`.

### 2026-08-11 (the invalidation that was never happening, and what the MSI fault is not)

**A bug this file introduced on 2026-08-06 and recorded as harmless.** Queued invalidation was
enabled then, to satisfy the specification before interrupt remapping, and written up as "it did not
fix anything and the code is more correct with it". The second half was wrong. **Setting `QIE` is
the moment the unit stops honouring the invalidation registers** — and it stops honouring them
*silently*: the command bit clears, the poll succeeds, and nothing is invalidated. Every
register-based invalidation left in the kernel became a no-op on any boot with `iommu=remap-irq`.

The kernel's own gate caught it the whole time and nobody read it:

```
iommu window   FAILED: the context cache did not invalidate
```

It only appears with remapping on — which was the boot that was already red for the undelivered MSI,
so a new failure line read as part of the known one. QEMU said it too, twice a boot: `Queued
Invalidation enabled, should not use register-based invalidation`.

**Fixed** by submitting context-cache and IOTLB invalidations as queue descriptors when `QIE` is
set, with an invalidation-wait descriptor for completion rather than the head register catching the
tail — the head advancing says the descriptor was *taken*. The register path stays for the ordinary
boot, where the queue is off. Both encodings are pinned by host tests. Afterwards: QEMU's complaint
gone, the context-cache gate green, `test-boot`, `test-boot-iommu` and `test-host` clean.

**It did not fix the MSI, and that is worth recording as an eliminated cause rather than a
disappointment.** Same boot, after the fix: still `0 deliveries`.

**What the MSI fault is now known not to be.** All of this is read-back and trace evidence, not
inference:

| Ruled out | How |
|---|---|
| The MSI-X table entry | Read back from the device: `[0xfee00038, 0, 0, 0]` — handle 1, both format bits, unmasked |
| MSI-X being off, or function-masked | Control reads back `0x8001`; QEMU independently reports `enabled 1 masked 0` |
| The IRTE | `irte[1] low=0xfc0001 high=0x40018` — vector `0xfc`, source id `00:03.0`, present |
| The device being wedged | It completes **274 requests** under remapping, against 419 without |
| Stale context cache or IOTLB | Fixed above; the fault is unchanged |

**Which narrows it to one gap**: between a request completing and a message being sent. With
remapping off, 419 completions produce ~143 messages at the unit; with it on, 274 completions
produce **none**. Nothing in this kernel sits in that gap — it is the device model deciding whether
to raise the interrupt at all.

**A red herring, named so it is not chased.** The trace shows a message `(addr 0xfee00000, data
0x0)` that looks exactly like a device MSI built from a zeroed table entry. It appears in the
**working** boot too. It is not the block device and it is not evidence of anything.

**The next thing to look at** is the gate itself: what the device model reads to decide whether to
notify, which for virtio is the driver's available-ring flags read back over DMA. That is the one
thing in the path that is both guest-supplied and read through translation, and it is the only
remaining difference between a boot that delivers and one that does not.

### 2026-08-10 (the other two parsers, and a checksum that was hiding a quarter of one)

`elf::parse` closed its half of §8's fuzz requirement earlier today. `ustar` and `DMAR` close the
rest — and the second of them was not the routine one it looked like.

| Target | Executions, two hours at three workers | Result |
|---|---|---|
| `fuzz/ustar_parse` | **96,020,255** | no crash, no timeout, no OOM; 157 edges, 694 features; corpus 421 → 523 |
| `fuzz/dmar_parse` | **2,450,756,142** | no crash, no timeout, no OOM; 127 edges, 428 features; corpus 23 → 147 |

Replaying both final corpora reports `slowest_unit_time_sec: 0`, at peak RSS of 118 MB and 36 MB.
Nothing loops, and nothing grows without bound.

**The `DMAR` target's first campaign was fuzzing the doorway.** It plateaued at 23 corpus units
within seconds, and only nine of those summed to zero. An ACPI table carries a checksum over *every
byte of the table* and `parse_dmar` refuses anything that does not sum to zero — correctly, since
that is what the firmware interface says. For a fuzzer it is a wall: every mutation of a table that
passes lands one that does not, so guidance keeps rediscovering the header and never gets down the
corridor. The target now parses each input twice, once as it arrived and once with the signature,
length and checksum made consistent.

**What the wall cost, measured.** Three variants over `parse_dmar`, differing in exactly one thing,
each from an empty corpus with no seed inputs, at a fixed execution budget, two libFuzzer seeds
apiece:

| Variant | Parses per execution | Budget | Edges, seed 1 / 2 | Features |
|---|---|---|---|---|
| As it was — no repair | 1 | 30,000,000 | 86 / 80 | 147 / 137 |
| As it was — double budget | 1 | 60,000,000 | **86 / 80** | 152 / 136 |
| Repair only | 1 | 30,000,000 | 103 / 103 | 326 / 313 |
| Both parses — what ships | 2 | 30,000,000 | **116 / 116** | 366 / 368 |

**A quarter of the parser was unreachable, and budget does not buy it back.** Doubling the
unrepaired budget returned *exactly* the same edge count — 86 and 80, unchanged — so it is
saturated rather than merely slow. The unrepaired target also executes about 1.6× faster per run,
which puts 60 million past wall-time parity with the 30 million repaired runs: the comparison is
generous to it, and it still loses.

**Both parses are kept, and the measurement is why.** Repair alone reaches 103 edges where the pair
reaches 116. Those 13 are the rejection paths — the short buffer, the wrong signature, the length
that disagrees with the buffer, the checksum that does not add up — and only an input that fails
them proves they reject. A target that only repaired would have reported a clean campaign over a
gate it had never tested.

The general rule this buys, now recorded in [coding-style.md](docs/coding-style.md) §8 beside
M6-03's: **a parser guarded by a whole-input checksum is unreachable to a fuzzer that does not
repair it**, and a target that does not say so reports a clean campaign over the doorway.

**Two things this does not cover.** `ustar`'s 96 million executions against `DMAR`'s 2.45 billion is
not a like-for-like number: its inputs are archives, its corpus is 25 MB, and a unit costs about
twenty-five times more to execute. Both stopped finding new edges long before the campaign ended,
but the smaller number is the one to grow next. And the duration in M6's exit criterion is still
unmet — it says 24 hours, and this says two.

**Addendum, the same evening: `ustar`'s number grown, and the obvious lever was the wrong one.**

| | Executions, two hours at three workers | Result |
|---|---|---|
| `ustar`, uncapped | 96,020,255 | 157 edges, 694 features |
| `ustar`, `-max_len=16384` | **249,838,036** | no crash, no timeout, no OOM; 155 edges, 537 features; corpus 168 → 206 |

The obvious lever was `cargo fuzz cmin`, and it bought **nothing**. It reduced the corpus from 523
files and 25 MB to 168 and 8.8 MB with coverage preserved exactly — 146 edges and 683 features on
replay, unchanged — and throughput went from 2,525 to 2,543 executions a second on identical
copies, which is noise. Both replays had already reported `corp: …/8521Kb`: libFuzzer was
discarding the 355 redundant files at load on *every* run, so `cmin` only made permanent on disk
what the fuzzer was doing in memory anyway. It is worth doing for startup and disk, and it is not a
throughput fix.

**The cost is per-byte, not per-file.** A `tar` payload costs bytes without adding parser logic —
the walk steps over it and `data()` is a slice — so an archive's size buys very little. Capping
input length is worth 5.4× the executions for two edges: 13,650 a second against 2,543, at 144
edges against 146 on load. The campaign above confirms it at scale, reaching 155 of the uncapped
run's 157 edges while executing 2.6× as many inputs.

**Which leaves features, not edges, as what the big archives were buying** — 537 against 694, and
that gap is real. Long archives combine states that short ones cannot, so the capped run is the
better default and not a replacement. The next long campaign should be capped; an occasional
uncapped one keeps the realistic initrd in the corpus.

### 2026-08-10 (the ELF loader's fuzzing, which this file has owed since M6)

Two campaigns, neither of which found anything, and the pair is the point: one of them could not have.

| | Inputs | Result |
|---|---|---|
| Seeded mutation, 12 batches over disjoint seeds `0…12e9` | **12,000,000,000** | no panic, ~2h55m |
| Coverage-guided (libFuzzer, `fuzz/elf_parse`) | **901,322,222** at 125k/s | no crash, **2,054 new coverage units**, no unit slower than a second, peak RSS 600 MB |

**The seeded harness was re-running the same billion inputs.** It walks `0..iterations`, so a longer
campaign was not a wider one — twelve batches would have tested one billion images twelve times.
`BHASKIX_FUZZ_SEED_BASE` fixes that, and the twelve billion above are distinct.

**Coverage guidance is what §8 was asking for, and the difference is measurable.** 2,054 inputs each
reached code the previous inputs did not; blind mutation produced none the harness had not already
seen. `slowest_unit_time_sec: 0` is the quietly reassuring one — no input made the parser loop on a
length its own header chose, which is the failure a loader is most prone to.

**Three gates had to be satisfied, and each was right to object.**

- **The kernel's global allocator aborted the fuzzer on its first allocation.** `heap.rs` already
  carried a comment predicting exactly this — for `cargo test`. But `cfg(test)` is set only for the
  crate's *own* tests, and a dependent host binary compiles the kernel in non-test mode and inherits
  an allocator backed by physical memory that does not exist. The hazard was documented and the
  guard still did not cover the door the fuzzer came through. A `host` feature closes it; no kernel
  build sets it.
- **`bhaskix-fuzz` had no declared unsafe budget.** Zero, and it must stay zero: a fuzz target that
  needs `unsafe` to reach a parser can manufacture its own crashes.
- **`libfuzzer-sys` is the repository's first external dependency**, and `ALLOWED_EXTERNAL` was
  empty. Allowlisted rather than hidden behind a skip path, so the exception is visible to anyone
  auditing dependencies. The shipped kernel still has none: `fuzz/` is its own workspace, host-only,
  nightly-only, and never linked into anything that boots.

**What this does not cover.** `ustar` and the `DMAR` parser still have only the seeded harness. The
argument §8 makes about blind exploration applies to them unchanged, and now with a measured example
of the gap.

### 2026-08-09 (the second stall: the bootstrap CPU waited for seven CPUs on a four-CPU machine)

**Both bring-up stalls are now fixed.** This is the other one — the one this file spent a day calling
the `demand paging` stall, which it never was.

```rust
let requested = start(secondary_main);              // secondaries begin registering here
let expected = percpu::online_count() + requested;  // ...and are counted a second time here
```

`percpu::install` increments the online count as its **first** act, so a secondary counts the instant
it starts running. Reading the count *after* `start` returns therefore counts every CPU that won that
race twice — once in the count, once in `requested`. On four CPUs the bootstrap CPU waited for
**seven**, a total that can never arrive. The fix is to snapshot the count *before* the call.

**How it was found, because none of it came from reading the code.**

- The two failing logs ended with a **complete** `demand paging` line, byte-identical to a healthy
  boot's. The stage that never printed was the next one, `cpus N online of N` — so the fault was in
  SMP bring-up, and the label had been sending readers to the wrong subsystem since it was first seen.
- A **register dump of the hung machine** (QEMU monitor, all CPUs, KASLR slide subtracted) put the
  bootstrap CPU at `smp.rs:157` — the bounded wait — and all three secondaries at `cpu::halt`,
  *healthily idle*. Those two facts are contradictory: halted secondaries **are** online. That
  pointed at `expected` being wrong rather than at the secondaries failing, which is what turned a
  week of reading into an afternoon.
- A `println!` inserted between `start` and the wait **widened the window enough to make a 1-in-330
  race fire on every boot**. That accident is what made the bug tractable.

**Verified twice, the first time being the stronger.** With the race-forcing print still in place —
the build that had hung 4 boots out of 4 — the fixed kernel booted **5 times out of 5**. Then **600
boots, no self-test failed**, slowest 19s, against about two expected at the old rate.

**A correction, and a latent issue left open.** The spin bound was dismissed earlier that day on a
measurement of 2 billion spins taking 6.4 seconds. That was *guest* time: the measuring boot took
**491 seconds of host wall-clock**, because the emulated TSC does not track the host clock. The bound
was not the cause, but the reasoning that dismissed it was wrong — and the bound is still a spin
count rather than a deadline, so a CPU that genuinely never arrives stalls the boot for minutes
instead of failing fast and naming it. Worth fixing; not fixed here.

### 2026-08-09 (the stall was a release order, and the two false alarms after it were mine)

**700 boots, no stall**, where about five were expected. The cause was not a missing lock or a bad
call site: it was the *order* in which a release gives things up.

**One mask was doing two jobs.** `held_mask` answers "where in the declared order is this CPU", and
`preempt` was reading it as "is this CPU holding anything". Those need opposite timing. The rank bit
must be cleared **before** the lock is released, or the next acquisition of that rank looks like a
second one and is reported against blameless code. A hold must be given up **after**, or there is a
window in which the lock is still held and the CPU reports nothing — and a tick landing there
carries the holder away with the lock still set, leaving a runqueue no CPU can ever take again. That
window is the bring-up stall, and it is why the dump said *held by nobody*.

The fix is a second piece of state, `sync::holds_any`, covering ranked and unranked acquisitions
alike, given up after the release while the rank bit is given up before it. Neither has to
compromise for the other.

**Two attempts in between were wrong, and both were caught by the soak rather than by review.**

| Attempt | What it did | How it failed |
|---|---|---|
| Move *both* to after the release | Correct for preemption | False ordering report, 1 boot in 700 — a wait-queue bit outliving its release |
| Count per-CPU, not per-thread | Simpler | Leaked across switches; 3 boots in 28, and it wedged the boot outright once `preempt` counted its own switch lock |
| Count after the rank bit on acquire | Looked symmetric | Two instructions claiming a rank with the count still empty — 1 boot in 30 |

The rule both halves now obey: **claim before you might hold, give up after you certainly do not.**
Over-claiming costs a skipped preemption; under-claiming costs a CPU.

**Three instruments were added and stay**, each a boot gate reading clean on a healthy boot, because
every hypothesis in this hunt that was argued rather than measured turned out wrong:

- `remote hold` — a thread descheduled holding *another* CPU's runqueue.
- `block holding` — a thread blocking voluntarily while holding a lock. `preempt` can refuse such a
  thread; `block_self` cannot, since a block that declines to block is a spin, so it reports and
  names the caller.
- `saved holding` — a thread switched out carrying ranks. This is the one that solved it: it named
  `ipc-cli-a` and `dom-a-0` being stored with masks they did not hold, which no amount of reading
  had produced.

Lock-order violations now print `file:line` via `#[track_caller]`. `blocking on SchedRunqueue while
holding SchedRunqueue` names a shape, not a line, and this kernel takes runqueue locks in some thirty
places.

**Verification, completed the same day.** The 700-boot run covers the release order. A further **300
boots covers the acquisition order: no self-test failed, slowest 20 seconds against a 120-second
cap.** Against the rates being fixed those numbers mean something rather than merely being large: the
acquisition-order fault ran at 1 boot in 30, so 300 clean boots stand against about ten expected
reports, and the stall at roughly 1 in 140 stands against **1000 boots with none, where seven were
expected.**

Two limits on that, because a clean number invites more than it supports. The soak harness keeps its
per-boot logs only on *failure*, so the run that passes leaves nothing to re-read — the boot counts
are from the summary, which covers stalls and ordering failures because both fail a self-test. The
two reporting-only gates, `saved holding` and `block holding`, were confirmed zero through boot 260
while the logs still existed and are unverified for the last forty; they print without failing a
boot, so the summary does not speak for them.

**A further 500 boots on 2026-08-09 put the fix at 1500 with none of this stall**, against about eleven expected at the original rate. That run failed twice — both the *other* defect, secondary-CPU bring-up, which was never claimed fixed — and all three lock gates read clean on all 498 boots that finished. `make soak` stops at its first failing target, so the shell half did not run and that day's shell total stays at 150.

**And 1000 boots prove less than they look, because a boot is not a workload.** Bring-up exercises
the release path this changed, but only until the milestone prints. **100 runs of the user shell,
none failed, slowest 21s** is the part that covers the machine actually being used — typing at the
shell, answered by console and filesystem services under sustained IPC, on a change that touched the
release of *every lock in the kernel*. A fix verified only by boots would have been verified against
the quietest thing this system does.

### 2026-08-09 (a hypothesis for the stall, instrumented, and refuted)

**The stall is not what this thought it was, and the entry exists to stop the next person walking the
same path.** A concrete mechanism was proposed, instrumented, apparently confirmed, fixed — and the
fix changed nothing.

**The hypothesis.** `try_lock` deliberately stays out of the ranked lock set: a non-blocking
acquisition can never be an edge in a deadlock cycle. `preempt` refuses to deschedule a thread
holding a lock, and it asked *that* set — so a `try_lock` holder read as holding nothing. `exit`
reaches `domain_of_raw` and `threads_in_domain_except` with interrupts enabled, and both `try_lock`
every runqueue. A tick in that scan would carry the exiting thread away still holding a **remote**
runqueue; a thread part-way through `exit` may never run again, so nothing would release it.

**The instrument.** `preempt` counts, at the moment of switching, any *other* runqueue whose owner is
this CPU — the exact event. It counts and does not prevent, because a fix that made a 1-in-125 stall
stop reproducing would be indistinguishable from luck. Reported on **every** boot, healthy or not.

**The apparent confirmation.** 55 boots: 54 healthy at zero, and the single stalled boot non-zero,
holding another CPU's runqueue. Clean contrast — and **a correlation on one sample**, which is what
it should have been called at the time.

**The refutation.** With the guard in place, **3 boots in 500 stalled against 4 in 500 without it** —
the same rate. Worse for the hypothesis, one of the three (`run-133`) arrived with the *identical*
signature the guard was supposed to make impossible: cpu 2 holding cpu 0's runqueue.

**And the 500 boots found two more things.** The three failures were three different faults:

| Boot | What it was |
|---|---|
| `run-133` | The original signature, unchanged, with the guard in place |
| `run-490` | cpu 0 held for all 20 samples **while the lock records no owner** |
| `run-241` | Stalled at `demand paging`, before the scheduler — the known second stall point |

`run-490` is the one to pull on. A lock held continuously for two seconds that names no holder means
the two claims cannot both be true, and it points somewhere else entirely — at `locked` being left
set rather than a holder being descheduled. **That branch was written on 2026-08-09 as the case that
"has not been seen fire and is not claimed to have been", and it has now fired.**

**What was kept, and why.** The guard and the instrument both stay. Descheduling a `try_lock` holder
is unsound whether or not it is *this* fault, and the counter is now a permanent gate reading zero on
healthy boots. Neither is a fix, and the code and `coding-style.md` §7 both say so in place, because
a rule justified by a bug it did not fix will otherwise be remembered as having fixed it.

### 2026-08-09 (the owner field earned itself: the dump now points at a CPU that looks healthy)

300 boots, two at a time, on an idle host (mean 63%, min 52%): **2 did not finish bring-up**, and both
were caught with the lock's owner recorded for the first time. With yesterday's 200-boot run that is
**4 stalls in 500 boots**, converging on about 1 in 125 — rarer than the original 1-in-70 estimate.

**Both dumps name cpu 2 as the holder of cpu 0's runqueue, and cpu 2 looks perfectly well.** Its own
runqueue reads 20 of 20 readable and its threads are listed normally; the CPU that goes silent is cpu
0, the victim. Every dump before this pointed at cpu 0 and said in as many words that it could not
tell you who held the lock — so the search would have started at the one CPU that is innocent. That
is the entire value of the field, collected on its first real outing.

The two captures agree in every particular: same holder, same victim, `ipc-cli-a` **Running** on cpu
2, `ipc-svc` **Finished** on cpu 1, and every IPC counter zero.

**Where the lock comes from is now known; why it is never released is not.** Only two paths take a
*remote* runqueue lock, and reading both narrows the question:

- **`wake_with`** takes a blocking `lock()` on each runqueue in turn, **iterating from cpu 0 upward**.
  Any thread anywhere waking anyone touches cpu 0's lock first. This is the likeliest reason the
  victim is always cpu 0, and it is an artefact of iteration order rather than anything about cpu 0.
- **`try_steal`**, from `preempt`, holds `mine` *and* `theirs` at once — apparently against this file's
  own "one queue lock at a time" rule, but not so: the second is a `try_lock`, which can never be an
  edge in a deadlock cycle, and `preempt` masks interrupts across the whole section.

**Checked and cleared**, so nobody reads them again: `preempt` refuses to deschedule a thread holding
a lock; `block_unless`'s two closures in `notify.rs` touch only atomics as its contract demands; and
`mark_domain_dying` really does take one queue at a time and wake outside every lock.

**The asymmetry worth pursuing, and it is not yet a finding.** `try_lock` deliberately does not join
the held set — there is a test asserting exactly that — while `preempt` skips only when that set is
non-empty. **A thread holding a runqueue lock acquired by `try_lock` is therefore invisible to the
protection that keeps lock holders on the CPU.** Inside `preempt` the interrupt mask covers it. An
unmaskable event in that window is covered by neither.

**Two samples are not a pattern.** They cannot distinguish "cpu 2" from "whichever CPU runs
`ipc-cli-a`", and the victim's identity has the mundane explanation above. Nothing here is a fix, and
the defect stays open.

### 2026-08-09 (the lock records who took it, so the dump stops naming the victim)

Yesterday's stall capture could say a runqueue had been held for two seconds and could not say by
whom — it printed that the CPU it named was *where the lock was, not who took it*, because `spawn_on`
and the wake paths block on a remote runqueue. Honest, and it left the reader with the one question
that matters.

**`SpinLock` now carries an owner.** The acquiring CPU is recorded on both `lock()` and `try_lock()`,
and `SpinLock::owner()` reads it back. `sched::runqueue_owner` exposes it for the watchdog, which now
prints one of three lines instead of a disclaimer: held by its own CPU, held by another (naming which,
and calling the reported CPU the victim), or — held twenty times running yet recording no owner —
that the two claims cannot both be right and the bookkeeping is as suspect as the stall.

- **Diagnostic only.** Nothing in the locking protocol reads the field. It is four bytes per lock and
  two relaxed stores per acquisition, on a path that already does a compare-exchange.
- **`try_lock` records an owner, though it is exempt from ranking.** The exemption is a statement
  about deadlock *cycles* — a non-blocking acquisition can never be an edge in one. It says nothing
  about holding: a stuck `try_lock` holder wedges a runqueue exactly as thoroughly.
- **The owner is cleared before the release, not after.** In between the two the lock is free, so
  another CPU may take it and record itself, and a later clear would erase a live owner — leaving the
  lock reading as unheld while somebody holds it, wrong in precisely the case the field exists for.
- **`percpu::cpu_id()` answers `0` before per-CPU areas exist**, so an owner recorded that early names
  cpu 0 for everyone. Said in the doc comment rather than left to be discovered; every caller so far
  runs long after.

**Verified in both directions, and against the real shape.** Three host tests cover record, clear, and
that a losing `try_lock` disturbs nothing. Then a boot with cpu 0 made to hold *cpu 1's* runqueue —
the defect's actual shape — printed `HELD BY cpu 0, which is not this one. cpu 1 is the victim`; and a
boot holding its own printed `HELD BY cpu 0, its own CPU`. Both read off the serial log. The
anomaly branch has not been seen fire and is not claimed to have been.

**This does not fix the stall**, and nothing here should be read as progress on it. It makes the next
capture name a CPU to go and look at instead of one to rule out.

### 2026-08-09 (the shell half, run on its own, and it stayed up)

The previous entry's soak stopped at its first failing target, so `soak-shell` never started. Run
separately on an idle host (~97%): **50 runs of the user shell, none failed, slowest 20s.**

Recorded because this one could have said something. At the 3% the `Status::Congested` defect was
seen at, fifty runs should turn up one or two failures, and a clean fifty happens about a fifth of
the time — where the 10-run pass the day before was the expected outcome whether or not the defect
was there. It leans toward the rate being lower than believed and settles nothing. **The machine was
capable of failing that night**: the same host, hours earlier, reproduced the bring-up stall twice
in 200 boots. The defect stays open.

### 2026-08-08 (the stall was caught, and the line that caught it was the one added that morning)

**200 boots, one at a time, on an idle host: 2 did not finish bring-up.** Mean 79% idle, minimum 57%,
and the 198 that passed took a steady 16–17 seconds against a 120-second cap — so the two are the
kernel, not the host. This is the §3 stall reproducing at 1 in 100, against an earlier estimate of
about 1 in 70.

**The watchdog fired on a real stall for the first time.** Every previous sighting of its output was
manufactured by shortening its deadline; these two were caught at 45 seconds on a boot that had
genuinely stopped.

**And the fact that identifies the stall is the one the thread walk could not say.** In both dumps a
CPU contributes *no threads at all* to the walk — before this morning's change that CPU was
indistinguishable from one with nothing scheduled on it, and the dump's most important content would
have been an absence. Instead each says it outright: `runqueue readable 0 of 20 samples over 2
seconds`. Held throughout, so not a thread waiting for a wake, which leaves the lock free and the
threads readable.

- **The signature.** Last line `syscall entry armed`; one CPU's runqueue held continuously; every
  other CPU readable 20 of 20 and listing its threads normally.
- **Not IPC.** `dropped`, `wake_missed` and lost deferred wakes were zero in both. The counters that
  would have implicated the mailbox path exonerate it instead.
- **Not a fixed CPU.** cpu 1 in one run, cpu 0 in the other. The caution printed beside the line
  matters here rather than being decoration: `spawn_on` and the wake paths block on a *remote*
  runqueue lock, so the CPU named is where the lock is, not necessarily who holds it.

**The shell half did not run.** `make soak` stops at the first failing target, so `soak-shell` never
started and the `Status::Congested` defect gained no evidence either way.

**One of the two dumps, in full**, because it is the evidence and a path into a temporary directory
is not — the run logs did not outlive the session that made them:

```
  BRING-UP STOPPED. 45 seconds have passed and it has not finished.
  The last line above is the last thing that completed. Every thread
  on this machine, and what it was doing:
    cpu 0  thread 3  boot  fair  Running  3957 runs
    cpu 0  thread 19  rt-probe  rt  Finished  51 runs
    cpu 2  thread 2  idle  idle  Ready  3880 runs
    cpu 2  thread 29  ipc-cli-a  fair  Ready  12 runs
    cpu 2  thread 30  ipc-cli-b  fair  Running  11 runs
    cpu 3  thread 1  idle  idle  Ready  3889 runs
    cpu 3  thread 27  watchdog  fair  Running  2 runs
  cpu 0: runqueue readable 20 of 20 samples over 2 seconds
  cpu 1: runqueue readable 0 of 20 samples over 2 seconds
           -- held for every sample. Nothing on this CPU could be listed
           above, and nothing on it can run. [...]
  cpu 2: runqueue readable 20 of 20 samples over 2 seconds
  cpu 3: runqueue readable 20 of 20 samples over 2 seconds
  ipc: 20 delivered, 20 replied, 20 receives returned,
       20 replies tried, 0 found no caller, 11 empty checks.
  0 messages were DROPPED because a mailbox was already full, and
  0 wakes went missing. Either is enough to strand a caller for ever.
  0 deferred wakes were lost.
```

**Read the thread list against the readability lines**: there is no `cpu 1` row anywhere in the walk,
and 34 lines of dump would have said nothing about why. The second failure is the same dump with the
roles of cpu 0 and cpu 1 exchanged. Reproduce with `make soak SOAK_RUNS=200 SOAK_JOBS=1` on an idle
machine, with `SOAK_LOG_DIR` set so the dumps survive the run.

### 2026-08-08 (the watchdog's thread walk was silent about the CPU that mattered most)

The dump added earlier the same day lists every thread by walking the runqueues with `try_lock`, and
**skips a CPU it cannot read without saying that it skipped one**. The skip is correct — the walk
runs from a watchdog that must not block — but it is invisible, so a CPU whose runqueue is held
contributes no lines and looks exactly like a CPU with no threads. The first dump this mattered on
had no `cpu 0` rows at all, and its most important fact had to be inferred from an absence, which is
the failure the watchdog was built to end.

- **Every CPU now gets a line, healthy ones included**, reporting how many of 20 samples found its
  runqueue readable. A line printed only on the bad case cannot be told from a line that failed to
  print.
- **Sampled rather than read once**, so "held throughout" is distinguished from "held at the instant
  we looked" — a single `try_lock` failure means only that someone held the lock for a microsecond.
- **All CPUs are sampled in each round**, not one CPU watched for two seconds before moving to the
  next. Per-CPU windows would sit two seconds apart, so a lock released between them would read as
  never held and one held in both as held continuously — neither true of any single instant. Costs
  two seconds for the machine instead of two seconds per CPU.
- **It reports an unreadable runqueue, and does not name a culprit.** The first draft of this line
  said the CPU was "wedged holding its own lock". That is not established by the measurement and can
  be false: `spawn_on` and the wake paths take a *remote* runqueue lock and block on it, so a CPU
  stuck in either strands the queue it reached for rather than its own. The line would then have
  named the victim and let the culprit go unmentioned. It now says the runqueue is held, says a
  waiting thread is not the explanation — a wait leaves the lock free and the threads readable — and
  says outright that which CPU holds it is not answered here.
- **Verified in both directions.** With the deadline shortened to 3 seconds a healthy machine prints
  `readable 20 of 20` for all four CPUs; with `runqueue_readable` forced false for one CPU the
  held-throughout branch prints, and both were read off the serial log rather than reasoned about.

**Soaked, and the soak did not exercise the new code.** `make soak` afterwards: **40 boots, none
failed** (slowest 18s against a 120s cap) and **10 user-shell runs, none failed** (slowest 21s). That
says the change does no harm on a healthy boot and nothing more — the watchdog arms at 45 seconds
and the slowest boot was 18, so **the lines added here never printed during the soak**. The evidence
that they print *correctly* remains the forced two-direction check above, which is a weaker thing
than a soak and is not worth confusing with one.

**A second, larger soak was started and abandoned, and is recorded as unrun.** 200 boots and 50
shell runs, sized so the two defects in §3 would be expected to appear rather than merely be given a
chance to. It was killed at 10 completed boots: three CI runner processes on this host were taking
about two of its eight cores throughout, boots had slowed from 18s to 81s, and the run was tracking
to 4.6 hours. A failure under that load could not have been attributed to the kernel — which is the
error this file already records once, where four concurrent guests on a loaded host were read as an
RFC 0017 regression and were not one. Nothing is claimed from those 10 clean boots. Rerun on an idle
machine with `make soak SOAK_RUNS=200 SOAK_JOBS=2 SOAK_SHELL_RUNS=50`, checking the host is quiet
first; `SOAK_LOG_DIR` keeps the per-run serial logs, which is where a watchdog dump would land.

### 2026-08-08 (a bring-up stall that says nothing now says what it was doing)

About one boot in seventy stops during bring-up and never prints again. Nothing in the tree could
report it, because every self-test bounds its own wait and reports its own failure — so a boot that
hangs has hung *below* the place that would notice, inside a blocking call with no deadline. And the
reporter cannot be another step in the bring-up sequence, because the bring-up sequence is what
stopped.

- **A watchdog thread asleep on the timer**, which is the one thing that still runs: the timer
  interrupt is independent of every lock and rendezvous in bring-up, and the idle backstop keeps
  CPUs alive to service it. If bring-up has not finished in 45 seconds it prints every thread — cpu,
  name, class, state, runs — and the IPC counters, including `dropped` messages and missing wakes,
  which until now were printed only on a failure path a hang never reaches.
- **It does not repair anything.** A watchdog that nudged the machine back into life would turn a
  reproducible fault into an unreproducible one, and the fault is the thing worth having.
- **Two placements were wrong, and each was found by a stall it failed to report.** Pinned to CPU 0
  it sat behind the boot thread: a thread spinning on a lock, or halted with interrupts off, never
  reschedules, so the watchdog never ran. It could only report the stalls that leave its own CPU
  free, which are the ones that need it least. Now on `online_count() - 1`. Spawned just before the
  IPC test, it could not see anything that stalled earlier; now armed straight after the tickless
  measurement.
- **Where it cannot be armed, and why.** Not before `sched::start_all` — a thread spawned into a
  stopped scheduler is runnable and never chosen. Not before `tickless_self_test` — that test
  measures how few interrupts idle CPUs take, and a watchdog asleep on a timer is an outstanding
  deadline on its CPU, so it would be grading the watchdog rather than the kernel. Verified that it
  is not: `1 ticks on 3 idle cpus`, unchanged.
- **Verified in both directions**, because an instrument that cannot be seen to fire is worth
  nothing: shortened to 3 seconds it prints the full dump mid-bring-up and the boot carries on; at
  45 seconds a healthy boot never triggers it.

**Two stall points, not one, and the second is out of reach.** `demand paging` stalls *before*
`sched::start_all`, so no watchdog built as a thread can ever see it — recorded in §3 rather than
papered over. `syscall entry armed` stalls after, and is what this covers.

### 2026-08-08 (three more ways a service could be killed, one of them a slow leak)

Found by auditing what else can refuse a `Recv`, since `serve()` exits on any refusal and only one
of its causes had been examined.

- **A dying thread left its endpoint queue entries behind.** `Endpoint::remove` was written for
  exactly this -- its own comment says *"for a thread that stopped waiting some other way — it was
  killed, or its domain was destroyed"* -- and for three milestones the only caller was `recv`
  cancelling *itself*. Nothing swept a thread that died. The entries do not decay, there are
  [`MAX_QUEUED`] = 16 per endpoint per direction, and when the last one goes every later caller is
  answered `Congested` for ever. `ipc::cancel_all` now sweeps from `sched::exit`, which all three
  death paths funnel through.
- **Half of every service death was invisible.** `Recv` is refused from two places -- resolving the
  capability, and the rendezvous -- and only the first called `note_recv_refusal`. The diagnostic
  built to explain services dying could not see the `ipc::recv` half. Both report now.
- **`serve()` exited on back-pressure.** `Congested` is the one status that says nothing about
  authority and everything about load. It now yields and retries; everything else still exits,
  which is still right.
- **The ABI did not know half the kernel's statuses.** `abi::status` was missing `BadSyscall`,
  `NotImplemented`, `NoDomain`, `Congested` and `NoSuchCaller` -- which is why a shell could only
  ever print `status 8` for the thing that was killing it. Added.
- **The gate, and what it is not.** `queue cleanup` builds the case on purpose: a thread queued to
  send on an endpoint nobody serves, then killed. Without the sweep it reports
  `the caller died and its entry stayed (Some((1, 0))); 1 of 16 slots in that direction are gone
  for good`; with it, nothing is left behind. The `endpoint queues` line beside it is a **monitor,
  not a gate** -- it reads the same either way, because bring-up never kills a thread while it is
  queued, which is why this leaked past every test for three milestones. Two earlier placements of
  it reported zero for a worse reason: they ran before any service existed, and "nothing wrong" and
  "nothing there" print identically.

### 2026-08-08 (the service bug, found: a contended lock reported as missing authority)

- **Root cause: `current_domain()` used `try_lock()?` on the runqueue.** One character of
  punctuation. A `try_lock` that fails because another CPU holds the lock for a moment returns
  `None`, `resolve_for_ipc` turns `None` into `Status::NoDomain`, and **a service told its receive
  was refused exits** — by design, because there is nothing left for it to serve. So a lock held
  briefly during one `Recv` did not slow a service down. It ended it, permanently, along with every
  caller that would ever queue behind it.
- **This is a conflation the tree already knows about and had not applied here.** `wake_with`
  documents it at length for wakes: *contended* and *not there* are different answers, and a caller
  that cannot tell them apart will pick the wrong one of retry and give up. `current_thread_id()`,
  called beside `current_domain()` on every path that reaches it, takes the same lock **blocking**.
  `current_domain` was the odd one out. Fixed by making it block, which is safe by the argument
  `trap::end_faulting_domain` already sets out.
- **The evidence**, from 72 runs with the refusal made loud:
  `A SERVICE WAS REFUSED A RECEIVE: thread 33 (consoled), status 7` — 7 is `NoDomain`. One log cuts
  off mid-word at `exit    end this s`: the console died while printing, and never spoke or read
  again.
- **Two hypotheses were disproved on the way, and both looked right.** A kernel was built with the
  old 8-slot `defer_wake` table and the drop made loud: 72 runs, two failures, **no lost wake**. A
  second diagnostic for "a server exited owing a reply" never fired either. Either would have been
  shipped as the fix on a plausible mechanism.
- **What actually found it was deleting a `let _ =`.** The shell answered `could not reach the
  filesystem` and threw away the status it had just been handed. `send_path` now returns the failing
  reply, `ls`/`cat` route it through `report_refusal`, and the `fs::RESET` status is no longer
  discarded either. `could not reach the filesystem` became `refused, status 7`, and that was the
  whole investigation.
- **`defer_wake` is still changed, as hardening and not as a fix.** Eight slots with no duplicate
  check, for a machine with up to `MAX_CPUS * MAX_THREADS_PER_CPU` = 512 live threads, is not a
  bound. It is now one slot per thread and deduplicated, so overflow is unreachable rather than
  unlikely. It was never observed to overflow.
- **Two defects remain open and are recorded in §3**: callers give up on `Congested` instead of
  retrying, and a boot still stalls occasionally *before any service starts* — earlier than
  anything fixed here.

### 2026-08-08 (hunting the filesystem-service bug: not fixed, but no longer invisible)

- **Not fixed.** The root cause is still unknown, and this entry exists so the next attempt starts
  from what was learned rather than from the beginning.
- **The soak was boldly testing the wrong machine, and I wrote it that way.** `boot-test.sh` attaches
  **two** disks — the second is what starts the block driver in its domain, the disk journal and the
  filesystem service — and my soak attached one. So it booted a machine with none of those and
  reported forty clean runs while the shell test failed one in twelve. Fixed: the soak now attaches
  both, with a private copy of the writable disk per concurrent run, and it reproduces the fault.
- **The hard fact, caught with new diagnostics**: `vfsd` was `Finished` after 98 requests, with
  **8 senders queued behind it and 0 receivers**. It exited. `serve()` exits when a receive is
  refused and has no other way out, so something refused it — and until now nothing recorded what.
- **What now records it**: `syscall::last_recv_refusal()` (which thread, which status),
  `ipc::abandoned_recvs()`, the endpoint's queue depths, and the service and probe thread states,
  printed at both the bulk-path and ring 3 failures.
- **Registers from a stalled machine** (QEMU monitor, KASLR slide subtracted) put CPU 0 in
  `ring3_self_test`'s wait loop with CPUs 1–3 **halted** — so the probe thread was not runnable at
  all, rather than running and failing.
- **It is one fault with several faces.** `ls`/`cat` unreachable; the ring 3 probe's calls not
  landing; the shell hung mid-`help`; and a silent stall after `syscall entry armed`. Every one is an
  IPC call that goes unanswered.
- **`make test` hits it too**, which is worth stating plainly: this is not a soak artifact, and the
  suite has been intermittently red for this reason for longer than anyone has noticed.
- **A caution for whoever picks it up**: the rate moves with host load, between about 1 in 12 and 1
  in 70. Thirty-five clean runs mean very little. Use `make soak-shell`, which has the highest rate,
  and read the diagnostics rather than the pass count.

### 2026-08-08 (the shell test is soaked too, and it found a real bug on its first run)

- **`make soak-shell`**, beside `make soak-boot`, with `make soak` running both. The boot soak asks
  "does it come up", repeatedly; this asks "does it *answer*", repeatedly. They are not the same
  question — last night's bug was in neither the boot nor the shell but *between* them, where the
  kernel's last output raced the shell's first.
- **Sequential by construction, and not by oversight**: the shell test writes to
  `build/domain-disk.img`, and the `disk` mode rebuilds the image outright. Two runs at once would be
  two machines writing one disk, and the failure would be reported against the kernel.
- **It failed on its very first run**, and has kept failing at about **one in twelve**. The
  filesystem service stops answering: `ls` and `cat` report they cannot reach it, and sometimes the
  kernel's own `bulk path` and `cost` self-tests fail beside it with `0/200 filesystem replies`. The
  failing runs finish in 25–29 seconds against a 240-second cap, so this is a check failing and not
  a clock running out — the distinction the harness now reports on purpose.
- **It is pre-existing.** Built the same soak against `3844ea3`, before any of the process-management
  work: it fails at the same rate, one in twelve, hanging at `ls /`. So the bug is not new; it is
  newly *visible*, because nothing in this project had ever run a test twice. Recorded as an open
  defect rather than fixed in the same change that found it.
- **The nightly job will be red some nights until it is fixed**, and the workflow says so. That is
  the correct behaviour for a job whose purpose is to find intermittent faults; retrying until green
  would remove the only thing it does.
- **Three distinct failure signatures were seen in about twenty-five runs**, which is worth recording
  because it suggests one cause with several presentations rather than three bugs: the shell hung
  mid-`help`; `ls`/`cat` unreachable with the kernel self-tests failing; and `ls /` hanging with no
  self-test failure at all.

### 2026-08-08 (the soak runs in CI, nightly, with its limits written down)

- **`.github/workflows/soak.yml`**: a job of its own, on a nightly schedule and on demand, not on
  every push. It answers a different question from the rest of CI — every other job boots once, which
  settles whether a fault is *there*; this settles whether one is *sometimes* there.
- **It is weaker in CI than on real hardware, and the workflow says so rather than leaving it to be
  discovered.** A GitHub runner has two cores and no KVM, so the guest's four processors are emulated
  onto two — and an oversubscribed host serialises exactly the interleavings a soak exists to find. A
  green run there means the machine boots repeatedly. It does not mean there is no timing-dependent
  fault, and the job's header says that in those words.
- **`SOAK_JOBS=1` in CI**, for the same reason. Concurrency on two cores does not buy parallelism the
  guest can use; it buys false failures, because a boot the host has stopped scheduling looks exactly
  like a boot that hung. That is not hypothetical — it is what this harness reported last night, and
  it was read as a kernel regression for most of an evening.
- **Logs survive a failure now.** The harness deleted its work directory unconditionally, so a run
  reporting "3 of 40 did not finish" left nothing to look at. It now keeps them on failure, prints
  where, and honours `SOAK_LOG_DIR` so CI can upload them.
- **Not done, and it is the obvious next step**: the soak boots, and boots alone. Last night's real
  bug was in the *shell* test, and a boot-only soak would not have caught it directly — it found it
  by proving the boot was deterministic, which left nothing for "the host was slow" to explain. A
  repeated shell run would have caught it head-on.

### 2026-08-08 (the shell test was never flaky — the kernel was tearing the shell's banner)

- **Caught live**, in a run that had been sitting at 492 seconds for a 20-second test:

      a user-mode s    address spaces 6 in use at once, each program in its own
        console out    every byte reached the wire
      hell. 'help' lists what it can do.
      bhaskix$

  The shell is alive and prompting. The harness is waiting for `a user-mode shell` as one string,
  and it arrived in two pieces, so it waits until its timeout and then reports every check as
  missing.
- **It had been found before and half-fixed.** The comment beside the shell's spawn describes this
  exact tear, and concludes that "the fix is to stop overlapping rather than to make the test
  cleverer". That fix moved two lines before the spawn. Two more lived in the *caller*, after
  `user_shell` returned, and kept tearing the banner for three milestones.
- **Every occurrence was written off as a loaded host — six times by me today alone.** That is what
  it looks like from outside: a test that passes standalone, fails under `make test`, and passes
  again when the timeout is raised. Raising the timeout *does* help, because a slower machine
  interleaves differently. The evidence that finally separated the two was the soak test showing the
  boot itself is deterministic — 20 boots, 14 seconds each, no variance — which left nothing for
  "the host was slow" to explain.
- **`make test` now passes at its default timeouts**, which it had not done once in this session.
- **A narrowing, stated**: the console-drop check moved before the shell starts, so it covers the
  kernel's output and not the shell's. The shell's output is checked by the shell test reading it
  back.
- **The lesson is about attribution, not about consoles.** A symptom with a plausible environmental
  explanation gets that explanation every time, and the explanation is unfalsifiable until something
  else rules it out. The soak test is what ruled it out, on the same night it was fixed.

### 2026-08-08 (the soak test, and a regression I reported that was not there)

- **`tests/qemu/soak-test.sh` has existed since M6-08 and nothing has ever run it.** Not the
  Makefile, not CI, not this file. Its own header argues for its existence — the M6-08 IPC stall
  passed the whole suite every run for weeks and then failed fourteen times in forty — and it was
  left where nobody would find it.
- **It never stopped a boot, which is why it was unusable.** This kernel does not power off, so every
  run cost the full timeout: forty runs took seventeen minutes whether they booted in fourteen
  seconds or hung in the first one. Worse, it made the two failure kinds indistinguishable — with the
  cap anywhere near the boot time, "did not finish bring-up" counted every boot the host had merely
  slowed down. Each boot is now stopped the moment it reports the milestone: **40 boots in 4m50s**,
  and the slowest is printed so the cap can be seen not to be near it. `make soak`, deliberately not
  part of `make test`.
- **I reported a regression that does not exist, and the correction matters more than the finding.**
  At the old defaults the soak said 4 of 40, then 3 of 30, while a pre-RFC-0017 worktree ran 30/30
  clean beside it. I read that as an intermittent hang introduced by RFC 0017 and said so. Then I
  measured it properly — one boot at a time, stopping each when it finished — and the current tree
  booted **20 out of 20 in 14 seconds each, with no self-test failure and no truncated log**. What
  failed was four concurrent four-processor guests on a host at load 8–15, against a 25-second cap.
- **Two lessons, and the second is the one I got wrong.** A harness that cannot separate "slow" from
  "stuck" will eventually report the host as a kernel bug. And a comparison between two trees is only
  evidence if the thing being compared is the tree — running both under the same contention is not
  the same as controlling for it, because which one draws the unlucky scheduling is chance.
- **Still true and still worth having**: nothing in `make test` runs anything twice, and both bugs
  named in the soak's header — M6-08's stall and RFC 0017 step 6's `sched::exit` ordering — are of
  the kind only repetition finds. `make soak` now costs five minutes and can be run.

### 2026-08-07 (what ends a lending — RFC 0016's last open question, answered)

- **A lent page can be given back.** `dir::RELEASE` unpins the frame *and* revokes what was handed
  over. Both halves, because either alone is worse than useless: unpinning without revoking leaves
  the caller reading a frame the cache may refill with another file's block, and revoking without
  unpinning gives the frame back to nobody.
- **Revocation's direction is the mechanism.** It goes down the tree and not up, so the service hands
  from a *lending* capability derived from its own — one per cache frame — and revoking that destroys
  the caller's copy while leaving the service's own untouched. Handing straight from its own would
  have meant the only way to take a page back was to stop using it.
- **The first version of both breakages caught nothing**, and the reason is the useful part: the
  second lend in the test was failing for an unrelated reason, so "0 pages still lent" and "cannot be
  mapped again" were both trivially true. A gate that passes because the thing it measures never
  happened is the same failure as a gate that does not measure anything. Chasing it turned up two
  real requirements — `REVOKE` needs `Rights::REVOKE`, and `HAND` needs `GRANT` **and** `DERIVE` on
  the capability it copies — so a lending capability carries four rights, each needed by a different
  party.
- **A file handle lives in one slot**, and the test's four `open`s each took it from the one before,
  so the handle needed for the release had been overwritten. Fixed by making the lending `open` the
  last of them rather than by re-opening, which would have lent a second time.
- **`bin/fsd` was built with a bare `cargo build` and stopped being loadable** — the fourth time this
  project has hit that. The Makefile's `RUSTFLAGS` are not optional, and `make` treats the stale
  artifact as up to date. It cost a boot that failed with *"not an ELF this kernel will load"* and a
  shell that hung on a service that was never there.
- **Still open**: a caller that never gives a page back. The service can only refuse the next lend.
  Taking one back unilaterally is possible with the same primitive and makes every lent mapping a
  fault waiting to happen, which should be measured before it is chosen.

### 2026-08-07 (RFC 0016 accepted)

- **Accepted, five steps implemented and gated**, and like RFC 0017 accepted *after* being built
  rather than before. Resolves **CR1**, which is a new decision-log entry: this RFC settles rules
  that should not be revisited without a superseding one — a reply may carry a capability, badges are
  one-way, and a directory is a badged endpoint capability rather than a kernel object kind.
- **Its first step has since caught its own author twice.** Badging being one-way refused the first
  working version of RFC 0017's `spawn`, correctly; and then silently refused a *breakage* written to
  test that a created domain holds nothing, which is how that check was found to be reading a quota
  counter instead of the child's CSpace. A rule that only ever agrees with you has not been tested.
- **Two open questions closed, two left.** `HAND` belongs on the endpoint — answered by the code,
  because there is no reply capability to put it on. The block service's missing `WRITE` was a gap
  rather than a question and closed in step 3. What ends a lending is **still open and acceptance
  does not close it**: step 5 lends a frame and nothing ever gives it back, which is bounded by a
  cache that refuses rather than reclaims, but bounded is not answered. Where `mkfs` lives is a
  documentation debt.
- **Every RFC describing work that exists is now accepted** — 0001, 0002 and 0008 through 0017. The
  five still marked *Draft — for discussion* (0003 storage architecture, 0004 OT gateway, 0005 Linux
  ABI, 0006 Kosh, 0007 livepatch) all propose work nobody has started, which is the honest reason
  they are drafts and not an oversight. Both accepted today were accepted on the evidence of working
  code rather than on the strength of the argument.

### 2026-08-07 (a bug shipped in step 6, found while accepting the RFC)

- **`sched::exit` was taking heavy locks after marking its thread `Finished`**, and it hung the shell
  intermittently — three runs in ten, in a different place each time. Shipped in `3bd2845` and fixed
  here.
- **The hazard was already written down**, forty lines away from the code that broke it. `dispatch`
  handles `Exit` before taking a single lock and explains why: a thread holding one cannot be
  preempted (M4-08), so a thread that reaches `exit` holding a lock spins there instead of leaving
  and nothing ever releases it. Step 6 made `exit` end the thread's domain — which takes the memory
  objects, the interrupt handlers, every runqueue, the domain table and the capability arena — and
  did it *after* marking the thread `Finished`. A thread that can never be scheduled again was put in
  the queue for all of them.
- **Fixed by ordering, not by locking differently.** The domain is ended while the thread is still
  `Running`, where it is an ordinary thread doing ordinary work. Asking "am I the last?" then needs
  `threads_in_domain_except`, because the thread has not yet marked itself gone.
- **How it was missed**: the boot gates and the fault gates passed every time, and so did the shell
  test on the runs used to verify the step. It took a docs-only change and a re-run to see 0, 1 and 3
  failures in three consecutive runs of the same image. An intermittent hang is not visible in a
  single green run, and nothing in the process asks for more than one.

### 2026-08-07 (RFC 0017 accepted)

- **Accepted, with all six steps implemented and gated.** That order is the point: this RFC is
  accepted *because* it was built, not before it. Four of the claims it made were wrong, and each was
  found by construction rather than by review — the process tree was not transitive over created
  domains, `GRANT` to a domain did not exist, a ring 3 fault cost a processor rather than the
  machine, and a domain handle must not derive from that domain's root.
- **The corrections stay in the document, in place.** An RFC edited until it matches the code is a
  record of what was built; one that keeps its wrong turns is a record of what was *learned*, and the
  second is worth more to whoever reads it next.
- **One open question decided by acceptance**: a thread spinning inside the kernel is a kernel bug,
  and no mechanism will be built to interrupt it. Building one would make it acceptable.
- **Three stay open, plus a fourth the implementation added** — whether a domain should end when its
  last thread exits whoever created it. That one needs the boot sequence to stop treating a domain as
  outliving its threads, which is a change to the boot code and not to this mechanism.
- **PM1 resolved.** Two older debts close with it: RFC 0013's unresolved question 1, open since M7,
  and M5's exit criterion, which had been recorded as met and was never true.

### 2026-08-07 (RFC 0017 step 6 — a supervisor in ring 3, and RFC 0017 is complete)

- **All six steps built.** A program creates a domain, gives it a capability, starts a program in it,
  is told when it ends, asks what happened, and gives the slot back. Every one of those is an
  operation on a capability, and none of them is a new syscall kind.
- **A handle to a domain must not be derived from that domain's root**, and step 4 had it wrong.
  Ending a domain revokes its root so that no authority outlives the program that held it — which
  took the creator's handle with it. A creator asking what happened to its child was told its
  capability had been revoked, and the slot the kernel had carefully kept could not be reached, let
  alone reaped. Authority *inside* a domain dies with the domain; a reference *to* one has to outlive
  it. Two different things that looked like one.
- **Method numbers are shared across object kinds, and the order of the dispatch blocks silently
  decides which kind wins.** `BIND`, `INFO` and `RELEASE` are all claimed by earlier blocks that
  resolve a capability their own way and `return` whatever that produced, including its failure — so
  a `Domain` invoked with `INFO` was answered `WrongObject` by the code for device windows, which had
  never heard of domains. All three of this step's methods were unreachable, and nothing said so.
- **The first fix was worse than the bug.** Asking the capability's kind on every invocation put the
  domain table on the hot path of every system call; the boot reached the scheduler tests and stalled
  with a 407 ms worst-case wakeup. Guarding by *method* instead takes those locks for three methods
  and not for all of them.
- **A limitation, recorded rather than buried**: a domain ends when its last thread exits only if a
  program created it. Several boot self-tests run a thread to completion and go on granting
  capabilities to the domain it ran in; ending those out from under them turned passing tests into
  `NoDomain`. A kernel-made domain is ended by the kernel that made it, and the consistent
  alternative needs the boot code to stop treating a domain as outliving its threads.
- **Retention is conditional**, and it has to be: a dead domain is kept only while its parent is
  alive to ask about it. Otherwise a table with 32 entries fills with remains no living program can
  name.
- **Two breakages, two signatures.** Not signalling the watcher leaves the supervisor blocked for
  ever — the exact failure the binding exists to prevent. Not retaining the corpse wakes it to find
  nothing to ask about.
- **`Domain::threads` was never maintained**: only one self-test increments it, so it reads zero for
  every domain in the system, and step 5's "this domain already has a thread" check could never fire.
  It now asks the scheduler.

### 2026-08-07 (RFC 0017 step 5 — a program starts a program, and `GRANT` turned out not to exist)

- **Done, and it was two steps.** `START` on a `Domain` capability loads an ELF and gives the domain
  its first thread. A program now creates a domain, gives it a capability, starts a program in it,
  and that program calls a service using the capability it was given — create, grant, start, end to
  end, from ring 3.
- **`GRANT` to a domain was `NotImplemented`.** The RFC said the creator transfers capabilities
  "using the `GRANT` that already exists". It did not: the dispatch answered `NotImplemented`, with a
  comment explaining why it could not be done *there* and nothing doing it anywhere else. So step 4's
  child could be given nothing. Built here in `HAND`'s two-stage shape, for `HAND`'s reason.
- **The image is a capability, not a filename.** `START` takes a `Memory` object the caller holds
  with `READ`. The kernel has no business opening files for a program. It is **copied** before
  parsing: the object belongs to a program that is still running and may write to it, and parsing
  headers a mutable third party can change is how a validated offset becomes a stale one.
- **The loading runs on the new thread**, not in the system call — an untrusted image's size should
  not be the caller's syscall latency, and a parser should not be on the dispatch path.
- **What a program gives away, it can take back.** The gate granted the child a copy of slot 0, and
  the probe revokes slot 0 at the end of its run to show revocation is transitive. It is: the child's
  copy went with it and the started program found itself holding nothing, so its call reached nobody.
  Half a day on that, and the finding is worth the time — a giver that wants what it gave to outlive
  its own housekeeping must keep a capability it does not intend to revoke.
- **Two of four breakages caught nothing**, because the probe never asked for those refusals. It now
  tries to start a program in an *endpoint*, and to give away a capability it holds without `GRANT`;
  both are refused, each with its own status, and each breakage now fails its own check.
- **A debugging `println` was masking the bug.** With it, the gate passed; without it, the started
  program's call vanished. The print delayed the service's reply, which kept the probe blocked, which
  kept it from reaching its revocation. A test that passes only when something is slow is a test
  reporting a race, and this one was reporting a real one.
- **`unsafe` 1087 → 1089**, justified: a second loader, deliberately not shared with the first,
  because the two answer to different callers and folding them would apply one's behaviour where it
  does not belong.

### 2026-08-07 (RFC 0017 step 4 — a program creates a domain, and an RFC claim was wrong)

- **The first object a program can bring into existence.** `SPAWN` on a `DomainControl` capability
  creates a domain and installs a capability to it in a slot the caller names. What comes back holds
  **nothing** — no threads, no capabilities, no address space — which is the argument against `fork`
  made structural rather than argued.
- **Two requirements, neither sufficient.** The capability says who may ask; the envelope's
  `max_child_domains`, zero by default, says how often. Either alone lets one holder exhaust a table
  with 32 entries in it, which is T10 through the door this step opens. Both watched failing.
- **An RFC claim was wrong, and building it is what found out.** The design said the process tree
  *is* the capability tree and killing a parent already kills its descendants "through machinery that
  is built and negative-tested". It does not: `create` inserts a domain's root into the arena as a
  **root**, not derived from its creator's, so revoking the creator reaches the copy it was handed
  and stops. Measured, not reasoned — a program created a domain, its creator was destroyed, and the
  child was still live. `destroy` now walks its children explicitly.
- **The parent link carries a generation**, not just a slot index. Slots are reused; a child
  recording "my parent is slot 5" would be claimed by whatever occupied slot 5 next, and destroying
  *that* would take an unrelated domain down with it. It cannot happen today because a child dies
  with its parent and may have no children of its own — but both of those are policy in `spawn`, and
  a mechanism should not be correct only while a policy holds.
- **The badge rule caught its own author twice.** RFC 0016 step 1 made badging one-way, and a
  domain's root is badged with its id — so deriving with badge zero is refused. It refused the first
  working `spawn`, which was right. Then it silently refused a *breakage* written to test that a
  child holds nothing, so the breakage did nothing and the check "passed" — which is how that check
  was found to be reading `held_capabilities`, a quota counter no direct install updates, instead of
  the child's CSpace. **A vacuous breakage is as dangerous as a vacuous test**, and this is the first
  time one has been caught in this project.
- **Five breakages, five signatures**: no kind check, no envelope check, no cascade, a child given a
  capability, and the vacuous one above once repaired.
- **The shell test needed `SHELL_TEST_TIMEOUT=1800`** to complete at load average 15–20. Not this
  change: 17 of 18 iommu runs were clean, and the one failure had *all* 31 checks failing, which is
  the signature of QEMU being killed rather than of anything the machine did.

### 2026-08-07 (RFC 0017 step 3 — and step 2 had a hole its own gate could not see)

- **RFC 0013's unresolved question 1 is closed**, open since M7: a caller blocked on a reply its
  server will never send is now told, rather than sleeping for ever.
- **Writing the test found that step 2 was incomplete.** `take_message_or_block` writes
  `State::Blocked` directly rather than going through `mark_blocked`, so it never learned the rule
  step 2 added. A dying thread asleep on an endpoint was woken, found nothing, and blocked again —
  permanently. Step 2 stopped every thread **except the ones asleep in IPC**, which is most of the
  ones worth stopping, and its gate could not see it because none of its three threads ever blocked.
  The lesson is not "one place was missed" but that a gate can only see the states its threads are
  in: three threads, none of them asleep, and the one state that mattered went unexamined.
- **The obligation is what dies, not the endpoint.** A caller blocked in `Call` cannot work this out
  for itself — the endpoint is still there, the capability is still good, and something else may
  serve it tomorrow. `exit` therefore takes the dying thread's `reply_to` and tells that caller.
- **`Status::Revoked`, not "no such endpoint"**, and the distinction is load-bearing: a caller that
  believed the endpoint had gone would throw away a capability that is still perfectly valid.
  Watched failing by reporting the wrong one, which fails that check and only that one.
- **Three breakages, three signatures.** No abandonment → the caller sleeps for ever. No `dying`
  check in the delivery decision → the server outlives its own domain *and* the caller sleeps.
  Wrong status → only the third check fails.
- **A duplicated match arm, left by a mangled edit.** A `python3 -c` in double quotes let a backtick
  in a comment run as a shell command; the file was written with the arm twice and the comment
  gutted. The compiler's unreachable-pattern warning is what found it. Edits go through heredocs.
- **The shell test timed out three times at load average 17–19** and passed at 8–11. Not this
  change: the same suite passes standalone in ~20s per mode. `SHELL_TEST_TIMEOUT` is 240s, which
  this box exceeds under the gitlab-runner; raising the default is a judgement call left open rather
  than made quietly.

### 2026-08-07 (RFC 0017 step 2 — a destroyed domain now takes its threads with it)

- **Done.** `destroy` marks every thread of the domain and wakes the sleeping ones; each stops at its
  next safe point. Before this it released the accounting and the authority and left the programs
  running — contained by having no capabilities, and not stopped.
- **A flag rather than a fifth `State`.** A dying thread is still `Ready`, `Running` or `Blocked`: it
  has not stopped yet, and everything reasoning about runnability, load and eviction must keep seeing
  it as what it is. A `State` variant would have to be handled by every one of them, and the ones
  that forgot would be the interesting bugs. Host-tested in both directions.
- **Sleeping is refused, not interrupted.** A dying thread is never marked `Blocked`, because
  sleeping is the one state with no next safe point. Waking the already-blocked ones is therefore
  the mechanism and not a courtesy — and it is most of step 3 arriving early.
- **The gate has three threads in one domain**: one faults, one spins in ring 3 making no system
  call, one does nothing but `yield`. All three must be gone. The spinner is the point: it cannot end
  itself, so anything that stops it stopped it from outside.
- **The two safe points are not equally provable, and this is the honest part.** Deleting the
  interrupt-return check is caught at once, and the diagnostic names the survivor — `spinner`, which
  has no other door. Deleting the **syscall-return check is caught by nothing**: a thread returning
  from a system call returns to user mode, where the interrupt check gets it within a tick. Measured,
  not assumed. It is kept for promptness and because step 3's woken-out-of-a-blocking-call case needs
  it, and `syscall.rs` says exactly that rather than implying the check is gated.
- **A diagnostic that went quiet exactly when needed.** The "which thread survived" report first
  asked `sched::domain_of` from inside `sched::for_each` — which runs its closure holding the
  runqueue lock, so `domain_of`'s `try_lock` failed and it answered `None` for every thread. It
  printed nothing at all in the one run where it mattered. Now matched by name.
- **`cargo fmt` moved an anchor again**, splitting a tuple across lines between writing an edit and
  applying it. The edit asserted its anchor and failed loudly instead of silently doing nothing,
  which is the habit that exists because four earlier edits did not.
- **Still not done: kernel stacks.** `reap_finished` frees a thread's slot and leaves its stack,
  because there is no allocator for stack slots. Older and larger than this step, and left as such
  rather than folded in.

### 2026-08-07 (RFC 0017 step 1 — an unprivileged program can no longer take a processor with it)

- **Done.** A fault in ring 3 ends that domain: the report is printed in full and unchanged, the
  domain is destroyed, the thread exits, and the boot carries on. M5's exit criterion is met four
  milestones after it was recorded as met.
- **The claim it fixes was overstated twice, and the third telling is measured.** `halt_forever` is
  `loop { disable_interrupts(); halt(); }` — the *calling CPU*, not the machine. A ring 3 fault took
  that processor permanently (no timer, no IPI can wake it) and leaked the domain, its envelope and
  its thread. On one CPU that is the machine; on four it is a quarter per faulting program. It read
  as total because the program used to demonstrate it was the shell, which is the only thing that
  prints — "nothing printed afterwards" and "the machine stopped" look identical from a console.
- **Two implementation details that are not optional.** Interrupts must be re-enabled before the
  thread exits, or `sched::exit` halts the CPU with them off and the fix is the bug wearing
  different clothes. And every line must be printed *before* `destroy`, because destroy is what a
  waiter watches for — the first version finished its report afterwards and it arrived shredded
  through the next three gates.
- **Why it is safe to take kernel locks in a handler**, which is the load-bearing argument: the
  faulting thread was executing *user* code, so it holds no kernel lock, so the domain table and the
  capability arena cannot be held by the thread this interrupted. That is why the path is reached
  only from the user-mode branch and is not shared with the kernel one.
- **The gate is `bhaskix.fault=user`**, behind the command line with the other six rather than in
  the boot sequence: a deliberate exception on every boot would force `shell-test.sh` to stop
  treating `EXCEPTION` as a failure marker, and a failure marker with an exception list will
  eventually ignore the wrong thing. It runs on **one CPU** — the harder case, where the machine
  continues only if the dying thread gives the processor back.
- **Watched failing three ways, each with its own signature**, which took fixing the harness to
  achieve. Restoring the halt loses everything *after* the fault. Leaking the domain loses only the
  gate line. A program that does not fault loses the report itself.
- **Two defects in `fault-test.sh`, found by needing it to tell those apart.** The missing-expectation
  list was only computed when the verdict was *success*, so a timeout never said what was absent;
  and because `timeout` kills QEMU at the deadline, the process was always dead by the time the
  verdict was decided, so every slow boot was reported as "qemu exited — check the image and disk".
  The timeout branch was effectively unreachable. Both fixed; the verdict now comes from `timeout`'s
  own exit status.
- **`unsafe` 1081 → 1097**, justified in `kernel/Cargo.toml`: one statement of real consequence
  (`enable_interrupts`) and a privilege stack for the gate, deliberately not shared with
  `ring3_self_test`'s — a test that borrowed another test's stack would pass on run order.
- **Not done, and named in the report rather than implied**: sibling threads of a dead domain keep
  running. `destroy` still zeroes a counter instead of stopping them, and when a domain has more
  than one thread the fault report now says so out loud. That is step 2.

### 2026-08-07 (RFC 0017 drafted — and a milestone marked complete on a criterion that was never true)

- **[RFC 0017](docs/rfc/0017-process-management.md) drafted**: process management as create, grant,
  start, kill, reap — each an operation on a capability, none of them a new syscall kind. Six steps,
  the first independently valuable.
- **Writing it found that M5 is `COMPLETE` with an unmet exit criterion.** The roadmap says a
  user-mode program *"is killed cleanly when it faults"*. It is not: a ring-3 fault calls
  `halt_forever`. Demonstrated by adding a temporary `crashme` to the shell — one null write from an
  unprivileged program with no capabilities stopped the machine, and took the console and filesystem
  services with it. **[Corrected later the same day, when step 1 was built and the claim was
  measured: `halt_forever` halts the calling CPU, not the machine. A ring 3 fault costs that
  processor permanently and leaks the domain, which on one CPU is the whole machine and on four is a
  quarter of it per faulting program. The shell made it look total because the shell is the only
  thing that prints.]** **No test here has ever faulted from ring 3**; all six injected faults are from
  kernel mode, which is why four milestones passed over it.
- **Three more gaps, each already documented somewhere and never collected.** `domain::create` takes
  a `&'static str` and all 21 callers are in `kernel/src/lib.rs`, so the set of programs that can
  run is fixed at compile time. `destroy` releases a domain's memory, interrupts and capabilities
  and **leaves its threads running** — `domain.rs` says so about itself. And RFC 0013's unresolved
  question 1, a caller whose service died, has been open since M7.
- **They are one problem.** Nothing happens when a domain ends, because ending is not an event. Once
  it is, the blocked caller is woken as part of it and the thread is stopped as part of it.
- **What the RFC refuses, and why it is written down**: no `fork` (it duplicates a capability space
  by implication, which is ambient authority arriving through the back door of a system built to
  refuse it), no pid (the process tree *is* the capability tree — killing a parent already kills its
  descendants, through machinery that is built and negative-tested), no signals (the two things they
  are used for are `KILL` on a capability you hold and a `Notification` the domain holds).
- **The envelope has to cover children or the RFC reopens T10**: `MAX_DOMAINS` is 32, and a domain
  that can create domains can exhaust the table for everyone else. Recorded in the RFC as a
  requirement of step 4 rather than a later refinement.

### 2026-08-07 (the status documents reconciled against this file)

- **README.md said "Status: M3 — memory management"** and, below it, "There is no user mode, no
  processes, no scheduler, no filesystem". All four exist, run in domains, and are gated. The status
  block now describes Phase 2 and names what is **not** there — no networking, no process
  management, no libc, the ELF loader's fuzzing still owed, nothing ever booted on real hardware,
  and Phase 0's review criterion unmet.
- **`docs/roadmap.md` labelled Phase 0 "(current)"** and listed A1–A5 as one unresolved row blocking
  M1 exit. A1 was settled by RFC 0001 and A2–A4 together by RFC 0008; only **A5** is open, and the
  row never blocked M1 in the first place. Phases and milestones now carry status markers, and the
  correction is written into the file rather than silently applied.
- **The roadmap still claimed the root was ambient** — "the last place in this system where holding
  one capability grants everything of a kind". RFC 0016 step 4 deleted it. A directory is a badged
  capability the kernel stamps, and there is no way up out of one.
- **README's build section was wrong about its own test suite**: "about 80 seconds", "17 host unit
  tests", "three project-invariant gates". Measured: **390 seconds, 327 host assertions, 492
  checks**, seven gates, four boot placements, four shell-test modes, six injected faults.
- **Scope kept where it belongs.** The roadmap owns milestone definitions and exit criteria, and not
  one of them was edited — only the status labels that were false, plus a banner saying this file
  owns status and roadmap owns scope. That division is rule §1 of this document and it is what
  stopped the drift being fixed in the wrong place.
- **Nothing here changes code.** Recorded because a documentation-only commit that also touches
  behaviour is how a status file starts lying again.

### 2026-08-07 (the tickless gate was reporting a real defect as a near-miss)

- **A gate failing one run in four was not flaky.** 165 ticks idle against 327 busy, three the wrong
  side of a 2× threshold. One CPU had been ticking flat out with nothing to run on **every boot
  since M4**, and two CPUs' worth of ticks in a window that should hold one is exactly that ratio.
- **The cause was ordering.** `scheduling_self_test` ends with `stop_all()` to freeze the world for
  reporting; `start_all()` sat four tests further down, so the gate ran inside the frozen window.
  `needs_preemption_tick` reads a stopped queue through the same `started` flag it uses for *early
  boot* — keep ticking, the timer is not proven yet — so every frozen CPU armed a slice it had
  nothing to preempt to. `stop_all` skips contended queues, which is why one CPU ticked and its
  neighbours did not.
- **The busy half was measuring nothing at all.** The burner threads were spawned into a stopped
  scheduler and never ran, so both windows counted the same frozen CPUs. A gate that appeared to
  test two states was testing one.
- **A machine-wide counter could not have found this**, and that is the lesson worth keeping: it has
  no term for *which* CPU, and a ratio against a busy baseline has room to swallow one broken
  processor in three. Now counted per CPU, bounded by a number derived from `IDLE_BACKSTOP_MS`
  rather than a ratio, retried instead of settled-for-a-fixed-time so host load cannot decide the
  answer, and it reports **why** a CPU is awake — what it armed for, and the threads it holds.
- Idle went from 165 ticks to 1. Watched failing both ways, with a distinct message for each.

### 2026-08-07 (RFC 0016 step 5 — the hand-over, and three negative tests that caught nothing)

- **Supersedes the entry below** that recorded the rule as proved and the hand-over as blocked. The
  hand-over is in: `bin/fsd` pins the frame holding a file's data and `HAND`s back a read-only
  derivation of that one page; the shell maps it and reads the file's bytes **out of the service's
  own cache**, with nothing copied.
- **The cache is eight one-page `Memory` objects**, not one object of eight pages. Forced rather
  than chosen: frames are not contiguous, so a single object cannot be handed out a page at a time,
  and handing over the whole object is the disclosure being avoided.
- **Three of four breakages caught nothing.** Making `pin` a no-op: not caught, because a lend
  nothing competes for proves nothing. Lending a frame by index rather than by the pin: not caught.
  Lending the whole cache object: not caught, because there is no whole to lend. Lending it
  writable: caught.
- **The fix was pressure, and the amount mattered.** Churning the cache by exactly its own size was
  still not enough — the frame just read is the last one an LRU cache gives up. At twice its size a
  deleted pin is immediate: the caller is handed the **directory** block, and both gates fail on the
  bytes. An intermediate version of this comment claimed a catch it had not made; the claim was
  wrong and was corrected before commit.
- **RFC 0016 is complete**, steps 1–5. M9-15 `DONE`.

### 2026-08-05 (RFC 0012 step 6, third attempt — the leading theory was wrong)

- **A newer QEMU fails identically.** 7.2 on the two-socket host behaves exactly as 4.2 does here,
  which kills the hypothesis I had been recommending as the next step. That is the most useful thing
  this round produced: the answer is in our code or our understanding, not in the emulator's age.
- **Four more theories eliminated**, all on the newer QEMU. The message *format* — compatibility
  fares no better than remappable. The *ordering* — enabling remapping after the device's interrupts
  already work breaks them immediately, and rewriting the table entry afterwards does not bring them
  back. The missing **invalidation queue** — the specification requires it before remapping, we were
  not doing it, and doing it changed nothing. And `zero sized buffers`, which QEMU 7.2 does not
  report at all.
- ~~**Queued invalidation is kept.** It did not fix anything and the code is more correct with it:
  register-based invalidation keeps working without it, which is exactly why the requirement is easy
  to miss, and it was missed here until an experiment went looking.~~ **Wrong, and corrected on
  2026-08-11**: it did not fail to fix something, it *broke* something. Enabling `QIE` is the moment
  the unit stops honouring the invalidation registers, and this kernel went on writing them — so
  from that day the context cache and the IOTLB were never invalidated on any boot with remapping
  on. See the entry for 2026-08-11.
- **What remains true**: the device completes requests throughout, the I/O APIC's remapped interrupt
  is delivered, and the device's MSI never reaches the unit in any arrangement tried.
- **The value of a wrong hypothesis, tested.** "Try a newer QEMU" was written into this file twice
  as the recommended next step. It was cheap, it was wrong, and the next person now spends that
  effort somewhere else.

### 2026-08-05 (RFC 0012 step 6, second attempt — two red herrings named so they are not chased again)

- **Still unsolved, and better understood.** Under remapping QEMU pops and completes about 140
  requests a boot, exactly as it does without it, so the device works and its DMA is fine. The I/O
  APIC's line is remapped and delivered. The one thing that never happens is an MSI leaving the
  device — the unit sees a remap request for the line and none for the device.
- **Two things that looked like the cause and were not**, both of which cost real time:
  `virtio: zero sized buffers are not allowed`, which QEMU reports at translation-enable time and
  which turns out to be the *firmware's* stale ring read through a translation that no longer maps
  it — it happens with remapping off as well, and the device reset that follows clears it. And
  `virtio_notify` tracing as zero, which is not evidence of anything: that event is not on the MSI-X
  path and reads zero in the configuration that works.
- **They are written into the code beside the flag**, not just here. A ruled-out list is only worth
  having where the next person will be standing when they need it.
- **The two encoding fixes stand on their own** — an IRTE destination at bit 40 rather than 32, and
  a format bit at 4 with SHV at 3 — and both are pinned by host tests. Either one produces an entry
  the hardware accepts and never delivers.
- **The recommendation is unchanged and now better supported**: try a QEMU newer than 4.2 before
  assuming the kernel is wrong. Two of this session's hardest faults were invisible until the
  environment changed. If a newer QEMU delivers it, the answer is upstream; if it does not, the
  remaining suspect is whether the queue's MSI-X vector assignment survives the table being
  rewritten.

### 2026-08-05 (RFC 0009 step 6 — and a negative test that took three tries to mean anything)

- **228 bytes in one round trip against fifteen by message.** The RFC's opening complaint was that
  bulk data moves at sixteen bytes a round trip, which is right for reading a filename and wrong for
  reading a file. The register path stays for the short case; `fs::READ_INTO` fills a shared region
  for the long one.
- **The measurement was flattering itself first.** The initial figure counted the path chunk and the
  open as part of the transfer and reported "76 bytes per trip". Opening a file costs the same
  either way, so the comparison is now the *data* path alone. A number that includes setup is an
  argument for the wrong thing.
- **The caller names a slot it holds, never an object identity.** An identity would be a caller
  asserting what it may reach, and a service that believed it would write into whatever was named.
  A slot is a caller pointing at authority it already has, which is checkable — the same shape the
  capability syscalls use.
- **The negative test proved nothing, twice, before it proved anything.** Naming an *empty* slot is
  refused by the lookup before any check of the capability. Naming a capability of the *wrong kind*
  is refused a second time by the generation check, so the gate still could not say whether rights
  had been consulted at all. Only a **read-only capability to the same object** isolates it: the
  caller genuinely holds it, it genuinely names memory, and the only thing that refuses it is the
  rights check. Disabling that check now flips the result.
- **The property it pins down is worth the three attempts**: a service asked to write into something
  the caller may only read must refuse, however genuinely the caller holds it.
- **`fs::READ_INTO` collided with `fs::RESET`**, both numbered 5. The compiler noticed only because
  a match arm became unreachable. There is a `const` assertion over the method numbers now, so the
  next collision fails the build rather than answering the wrong question.

### 2026-08-05 (RFC 0011 step 6 — the last blocked step, and a precondition written as code)

- **The step RFC 0011 would not take until there was an IOMMU.** There is one, so it is taken: a
  domain can hold an interrupt, bind it to a notification it owns, and acknowledge it. That is the
  first moment a driver could run outside the kernel and still be told when its device wants
  attention.
- **What a holder does *not* get is the MSI-X table.** An MSI is a memory write of an arbitrary
  vector to an arbitrary CPU, so a holder able to program one holds an interrupt injection
  primitive obtained by writing two words. The kernel programs it and delegates the rest.
- **The precondition is enforced rather than remembered.** `irq::name` refuses unless something is
  translating. A comment saying "do not do this without an IOMMU" is a comment; a refusal is a
  property. On a machine with no unit the self-test skips and says why, and the gate takes that as
  a pass — the honest outcome for a machine where the step is not safe to take.
- **Three refusals are the substance, not the success path.** A legacy line cannot be delegated at
  all: it is shared, and a holder that never acknowledges masks a line other devices need — a
  domain wedging its own device is its problem, wedging somebody else's is the kernel's. A
  `Notification` capability is not authority over an interrupt however much of it is held. And
  `BIND` checks *both* capabilities, so an interrupt cannot be aimed at another domain's
  notification.
- **The test puts the interrupt back.** It hands the block device's real handler to a domain, and
  `BIND` is precisely the authority to redirect an interrupt — so without `rebind_notification` the
  driver would spend the rest of the boot on the timer, working and slower, which is the quiet
  degradation this milestone keeps finding.

### 2026-08-07 (the nested-call defect — found, and it was in the syscall stub)

- **The user stack pointer was per-CPU, not per-thread.** The entry stub parked `rsp` in
  `gs:[16]` and the exit path restored it from there. A system call that **blocks** leaves that one
  shared word in place while another thread runs; the next ring 3 thread on that CPU to enter the
  kernel overwrites it; and the first thread then returns to user mode on **somebody else's stack**.
- **Why it hid for so long.** Every user program in this tree has its stack at the same address in
  its own space, so the wrong pointer is still *mapped*. The program does not fault — it reads its
  own memory at another thread's offsets, and carries on with plausible-looking garbage until
  something dereferences it. That is why it presented as a driver with a null `self`, a service that
  stopped answering, and a shell that printed fifteen characters: three programs, three symptoms,
  one word.
- **Why it needed a nested call to show.** Two ring 3 threads must be on one CPU with one of them
  *blocked inside a syscall*. A service calling another service is the ordinary way to arrange that,
  which is why it looked like an IPC defect for three attempts.
- **The frame already had the right value.** `user_rsp` is the first field of `SyscallFrame`, pushed
  on entry and then skipped with `add rsp, 8` on the way out — the comment beside it said "restored
  from per-CPU data below". Two instructions fix it: pop the saved value and repair the slot from it.
- **Watched failing** by putting the old exit path back: twelve gates fail and `bin/blkd` faults in
  `Virtqueue::describe` exactly as before.
- **Three wrong theories are now closed**, and they were wrong in an instructive way: a nested call
  faulting the caller, an address-space switch, and a shared privilege stack. Each explained *some*
  of the evidence. What broke the deadlock was the fault report naming the thread and its address
  space — added two commits ago for exactly this — which said "right space", and a register file of
  small integers that read as *somebody else's registers* rather than one bad pointer.
- **The reproduction stays in the tree.** Ten lines in the filesystem service that touch an uncached
  block while answering: the cheapest thing here that makes a service call a service.

### 2026-08-07 (the nested-call defect — a real bug fixed, the defect still open)

- **Not fixed.** Second attempt, and it is still open. What changed is that there is now a
  **ten-line reproduction** instead of a whole lending mechanism: in `bin/fsd`'s `OPEN_AT` handler,
  after a successful lookup, touch the file's own data block —
  `if target.kind == Kind::File && target.direct[0] != 0 { let _ = cache.page(target.direct[0]); }`.
  That block is not cached, so the service calls the block service **while it already owes its
  caller a reply**, and `bin/blkd` faults. Nothing else is needed.
- **What the evidence says now.** `thread 37 (blkd) expects space 0xf5a8000, cr3 holds 0xf5a8000` —
  the right space, so not an address-space defect. blkd faults at `Virtqueue::describe` with
  `self` = 1, and the whole register file is small integers: `rbx`, `rbp`, `r8`, `r9`, `r12`, `rdi`
  all 1, `rcx` 0x10, `r10` 8. That is not one corrupted pointer; it is a thread resumed with
  somebody else's register set — which points at a kernel stack or a `sysret` frame, not at IPC.
- **Ruled out this round**: the address space (the report says it is right); a missing callee-saved
  register in the context switch (all six are saved and restored); and the per-CPU privilege stack
  `user_shell_entry` installs — removing it changes nothing, though it remains redundant with the
  per-thread one the scheduler installs on every switch.
- **One real bug was found and fixed on the way.** `user/shell` and `user/fsd` declared the system
  call's method register as `in("rsi")`. The kernel pops the whole frame back on the way out, `rsi`
  included, so declaring it preserved tells the compiler something the machine does not promise.
  This project was bitten by exactly this once before, for the argument registers; `rsi` was the one
  that was missed. It is not the cause of the fault above — the fault survives the fix — but it is a
  live trap and it is gone.

### 2026-08-07 (RFC 0016 step 5 — the rule is proved; the hand-over is not)

- **A pinned frame is never the one reused**, and a cache with every frame lent refuses rather than
  taking one back. Three host tests; the headline one checks the lent frame after **every** eviction
  rather than once, because "eviction respects a pin sometimes" is not the claim.
- **My first version of that test could not fail.** It checked the pinned frame through `page`,
  which *wants* it — so the frame stayed permanently the most recently used and nothing would have
  evicted it, pin or no pin. It passed with the pin deleted. Now checked through `block_in`, which
  asks without wanting. Eleventh time in this project.
- **The machine hand-over is written and reverted.** One `Memory` object per frame — forced, because
  a cache in one object can only be lent whole and lending it whole hands a reader every other block
  in it — and a `MAP` method that pins and lends read-only. It reaches a fault in `bin/blkd`.
- **The new fault diagnostic earned itself immediately.** `thread 37 (blkd) expects space 0xf5b3000,
  cr3 holds 0xf5b3000` — the right space, so **not** an address-space defect. blkd faults in its own
  memory with a garbage `queue` pointer, reached when the filesystem service reads a block *while it
  already owes the shell a reply*.
- **So I withdraw a withdrawal.** I said the nested-call theory was wrong. The evidence for that was
  a lookup that happened to hit the cache and so made no nested call at all. This one misses, calls
  the block service mid-reply, and faults. The theory is back on the table and it was retired too
  early.
- **Four silent no-op edits in one session.** A scripted `.replace` whose anchor `cargo fmt` had
  reformatted matches nothing and says nothing, and the machine then behaves as though code that was
  never written is misbehaving. Every edit in the second half of this work asserts its anchor first.

### 2026-08-07 (RFC 0016 step 4 — done, and the defect was not what it looked like)

- **The namespace is out of the kernel.** `kernel/src/namespace.rs`, `ObjectKind::Directory`,
  `ObjectKind::File`, `method::OPEN_AT`, `Status::NoSuchName` and `Status::BadName` are deleted. A
  directory a program holds is a **badged endpoint capability to `bin/fsd`**: the badge carries an
  inode and a generation, the kernel stamps it so it cannot be forged, and the kernel no longer
  knows what an inode is.
- **All six RFC 0015 step 4 gates pass unchanged**, which is what they were written for: `inner: a
  file of 40 bytes`, `greeting: no such name in this directory`, `sub/inner` and `..` refused as
  names, the directory reachable, and a handle to a directory that is gone resolving to nothing.
  Same strings, same numbers, different mechanism, and the strings are how we know it is the same
  claim.
- **The defect that stopped this was mine, and it was not a nested-call defect.** `EXPECT` recorded
  *where* a capability could land and not *who was invited*, so it belonged to whichever call
  happened next — and a program that says where, prints a line, and then asks loses its declaration
  **to the console**, because printing is a call too. A declaration now names the endpoint it was
  made for, and nothing else can consume it. The clear-on-any-call-return that caused it is gone; it
  was there to stop a stale declaration being used by a later server, which addressing does properly.
- **Two earlier diagnoses are withdrawn.** "A server that calls while owing a reply faults its
  caller" was wrong: a nested call is fine, and the reproduction that seemed to show otherwise was
  this same `EXPECT` bug reached by a different route. The address-space theory built on top of it
  was wrong for the same reason. What was true in that investigation is only the part about
  identical link and stack addresses making fault reports useless.
- **A slice-based edit deleted two dispatch branches by accident** — `EXPECT` and `HAND` sat between
  `OPEN_AT` and the next comment I anchored on — and the machine said `hand refused 10`, which is
  `NoSuchMethod`, rather than anything about the missing code. Cutting by "from this comment to that
  one" is not a refactoring tool.
- **The six directory gates moved into the IOMMU-only group**, because they now need a filesystem
  service, which needs a block service, which needs a unit to contain the device.

### 2026-08-06 (the nested-call defect — sharpened, not fixed)

- **What it actually is, which is worse and more useful than "a nested call faults".** Moving
  `bin/blkd`'s stack away from `0x11000000` changed the symptom from silent corruption to a clean
  page fault at `0x11003e70` — a *stack address that is not mapped*. The shell was not corrupting
  itself; it was **running with another program's page table loaded**, writing to what it thought
  was its own stack and hitting blkd's, which is why blkd faulted with a garbage `self` and why
  nothing looked wrong until blkd's stack moved out of the way.
- **So the question is no longer "what does a nested call corrupt" but "why does a thread resume
  with the wrong `CR3`".** That narrows it to `finish_switch` → `enter_space`, which every switch
  path does reach — both `bhaskix_context_switch` sites and the new-thread trampoline. What has not
  been found is the path that resumes a thread without it, or the reason `enter_space`'s
  `current == root` short-circuit is wrong.
- **Ruled out along the way**: the space table being full (it prints when it is, and it never did;
  five in use of eight), `HAND` (removing it leaves the fault), `EXPECT` (the stale-handle probe
  takes the same path and answers), and the reply obligation itself (`reply_to` is taken and
  restored correctly, and a warmed cache with no nested call answers the same request).
- **A silent no-op edit cost an hour, for the second time in this project.** `cargo fmt` had
  reformatted a destructuring across several lines, so a scripted `.replace` against the one-line
  form matched nothing and reported nothing. The machine then behaved as though a store had never
  been written, because it had not.

### 2026-08-06 (RFC 0016 step 4 — stopped, on a defect worth more than the step)

- **A server that calls another service while it already owes a reply faults its caller.** The
  filesystem service must call the block service to answer a directory lookup — that is what a
  filesystem *is* once its disk is behind a service — and doing so kills the program that asked.
  Isolated by warming the cache so the lookup needed no device read: with no nested call, the same
  request answers correctly. It is not `HAND` (removed it, still faults) and not `EXPECT` (the stale
  handle takes the same path and answers).
- **What is built and working**: the `dir::` protocol; `bin/fsd` answering with the namespace rules
  moved out of the kernel unchanged; directory handles as badged endpoint capabilities, which only
  the kernel can mint and a client cannot forge; the disk carrying the tree the shell's gates
  describe. Two of the six gates already pass through the service.
- **The shell still uses the kernel's namespace.** Nothing regressed, and nothing is claimed that is
  not true — the step is not done and is not marked done.
- **Two diagnostic obstacles, one fixed.** Every program was linked at `0x10000000` *and* stacked at
  `0x11000000`, so a fault report identified nothing; `bin/fsd` now has its own code and stack
  addresses. Giving `bin/blkd` its own broke it in a way there was no budget to chase, and was
  reverted — the finding it produced is recorded below and did not need the change kept.
- **A claim I made here was wrong and is withdrawn.** I recorded that "the exception report's `rip`
  is not an instruction boundary". It is. The disassemblies that said otherwise were taken with
  `objdump --start-address` from an address that was not one, which desynchronises x86 decoding and
  produces a plausible-looking window of nonsense. The trap frame is correct.
- **The Makefile trap caught me a third time.** Building a user program with `cargo` by hand
  produces a binary at the path `make` checks, without the linker script, and the machine says
  `bin/fsd is not an ELF this kernel will load`. Only `make` builds these correctly.

### 2026-08-06 (the shell-start defect — a ring 3 thread that was not pinned)

- **One cause, three symptoms, and none of them looked related.** The block driver faulted with a
  null `self` inside `Virtqueue::describe` before touching its device; the console service answered
  one request and stopped; the user-mode shell printed fifteen characters and hung. All of it
  followed from `bin/fsd` being the first ring 3 thread in this system spawned **unpinned**.
- **Why that matters, and it was written down nowhere.** `install_kernel_stack` sets `RSP0` from the
  incoming thread's own kernel stack on every switch — *and returns early when that is zero*, which
  it is for a ring 3 thread whose privileged stack was installed for a particular CPU. Moved to
  another CPU, such a thread enters the kernel on **somebody else's stack**.
- **The rule is now checked at the one door into ring 3.** `enter_user` refuses an unpinned thread
  and says why. Watched failing by unpinning `bin/fsd` again: what was a day of chasing corruption
  in three unrelated-looking places becomes one line, and everything else keeps working.
- **The `unsafe` budget went up by one, and the surface went down by five.** Six loose
  `unsafe { enter_ring3 }` call sites became one behind a checked door.
- **Two diagnoses I had recorded as open defects were the same defect**, and both are closed. The
  "caller on the same CPU as `blkd`" theory was wrong: the caller was not *on* that CPU, it had been
  *stolen* to it.
- **What is still true and still unfixed** is the underlying limit: a ring 3 thread cannot migrate,
  because its kernel stack does not travel with it. Refusing to enter ring 3 unpinned is a guard, not
  a fix, and the guard says so.

### 2026-08-06 (RFC 0016 step 3, second half — the filesystem leaves the kernel, with two defects found)

- **`bin/fsd` mounts a real disk in a domain**, through the block service, and reads a file the
  kernel wrote into that filesystem through its own copy of the same crate. Two copies of one
  parser, one disk, the same answer.
- **The program contains no filesystem code.** It links `bhaskix-fs` — the same crate the kernel
  links — and supplies a `Store` made of system calls. That the crate needed nothing else is the
  return on RFC 0015 step 6: a filesystem written against a slice could not have been placed here.
- **Two programs were linked at the same address**, and it cost hours. `blkd` and every other user
  program sit at `0x10000000`, so a fault report saying `rip 0x10000515` resolved to a different
  function in each — and the wrong one was investigated first. `fsd` is at `0x12000000` now. An
  address is free; being able to tell which program faulted is not.

**Two open defects, both found here, neither fixed:**

- **A caller on the same CPU as `bin/blkd` that asks it for a sector makes the driver fault** — a
  null `self` inside `Virtqueue::describe`, before it touches the device. Reproduces every time,
  pinned or not; does not happen from any other CPU, where hundreds of identical requests succeed;
  and the shell, which *is* on the driver's CPU, calls it for something that does not touch the
  queue and is fine.
- **Starting `bin/fsd` stops the user-mode shell from starting.** The service runs and reads the
  disk correctly; the shell's thread is created and reaches its entry; and then nothing — no fault,
  no message, no prompt. Reproduces on every CPU tried, before or after the shell, with or without
  destroying the service's domain afterwards. The service is therefore **opt-in** (`fsd=on`), which
  is written at the line that reads the word rather than left to be discovered.

- **A flaky test explained and fixed rather than re-run.** The shell's banner was coming out through
  the middle of the kernel's last boot lines — `a user-mode s` … `boot cost …` … `hell. 'help'
  lists…` — because the shell was spawned *before* the boot report finished printing, and both write
  to one console. Only visible under load. The kernel now says everything it has to say before
  starting the program that shares the wire.

### 2026-08-06 (RFC 0016 step 3, first half — the journal reaches a disk)

- **`block::WRITE` exists, three milestones after it was promised.** RFC 0015 step 1 called for
  `READ` and `WRITE`; only `READ` was built, and nothing since needed the other half — so the
  journal had been proved exhaustively against an array in memory and never once against a device.
- **`DRAIN`, the mirror of `FILL`.** A caller names memory it holds and a service takes bytes *out*
  of it. Same three checks in the same order, and one deliberate difference: it asks the caller's
  capability for `READ` where `FILL` asks for `WRITE`, because the right demanded should be the one
  the operation performs. A fixed right would let a capability that may only be written to be read.
- **A filesystem on the virtio disk**, written through the block service in another domain, stopped
  one *device* write after its commit, recovered by mounting — and read back through a cache created
  seconds earlier that holds nothing, so what it reads is what the disk holds.
- **`args[1]` had always meant "how many sectors" and had always been ignored.** Every 4 KiB block
  was eight round trips and eight device requests. The service now carries eight sectors at once,
  which is one round trip per block.
- **The journal put 8 KiB on the stack per transaction** — a `[u8; BLOCK]` to build a commit and
  another to zero one — and a kernel thread ran off the end of its stack. It surfaced as a page
  fault with `rip == cr2` at an address inside the stack area, which reads as a wild jump and says
  nothing until the numbers are read. Both buffers are gone: a commit is built as the 56 bytes that
  actually say anything, and the log is cleared in the cache page rather than from a buffer.
- **Two negative tests caught nothing at first, for two different reasons.** `DRAIN` without the
  `READ` requirement changed nothing, because the only caller held its memory with every right — so
  the writer now also holds the *same object* write-only, and names that. And a write past the end
  of the device was refused with the check deleted, because QEMU's disk refuses it too — so the
  service now answers a range it refused **itself** distinguishably from one the device rejected.
  Ninth and tenth.
- The suite failed twice on a fixed 120 s boot timeout under external load (average 8–11, four
  gitlab-runner processes at 240% CPU). Measured rather than assumed: the new work adds **1.3 s** to
  a 22 s boot. Reran green at load average 8.

### 2026-08-06 (RFC 0016 step 2 — a service hands a program a capability)

- **`HAND` goes on the endpoint, and the RFC's open question is answered by the code**: there is no
  reply capability to put it on. `ObjectKind::Reply` exists in the arena but a server never holds
  one — the reply obligation is thread state and `Kind::Reply` ignores its capability argument — so
  "not answering anybody" is a *check*, and it is the one the tests spend most effort on.
- **The caller says where, with a new `EXPECT`.** The kernel cannot see the request's contents, so it
  cannot verify a claim that "the caller asked for slot N" — the server relays four registers. The
  caller therefore declares it as thread state, one-shot: spent by the capability that arrives and
  dropped when the call ends. Without it a hostile service could fill a slot a program was keeping
  **empty on purpose**, which the shell does and one of its own tests depends on.
- **`GRANT` and `DERIVE` are both required**, because they are different permissions: `DERIVE` is the
  right to make a weaker copy at all, `GRANT` the right to give one to somebody else.
- **Proved without a throwaway service.** The block driver lends the shell its device's configuration
  page, read-only — two programs in ring 3, and what crosses is authority rather than bytes: the
  driver never reads the page, the shell maps it and reads `1af4:1042` out of it. This needed an
  **IOMMU mode for the shell test**, because the block service only answers where a unit contains
  the device; without one the driver exits rather than serving, which is the refusal working.
- **Two of the three refusals were being tested vacuously**, and both were found by deleting the rule
  and seeing nothing fail. "A server not answering anybody" was refused with the rule deleted, for
  having declared no receive slot — so the driver now declares one first and the gate asserts the
  exact status. "A capability without `GRANT`" was refused by the *derive* first, because the
  capability chosen also lacked `DERIVE` — so the driver's windows now carry `DERIVE`, leaving
  `GRANT` as the only thing in the way. Seventh and eighth.
- **The shell test leaked a virtual machine per run.** It never stopped QEMU, leaving a four-CPU
  machine alive for the rest of its 240 s timeout, so the suite's shell tests overlapped — and with a
  fourth mode added they overlapped enough to fail one on a loaded box. Now stopped on the way out.
  This is the cause of at least two "flaky" failures recorded earlier in this project.

### 2026-08-06 (RFC 0016 step 1 — a badge is the granter's word, not the holder's)

- **Fixed the badge forgery found while drafting RFC 0016.** Badging is one-way now: a capability
  with badge zero is a master and may set any badge; one that already carries a badge may only be
  derived with the same badge. Rights stay monotone independently, so a holder can still pass on
  *less authority* — it just cannot pass on *a different identity*.
- **Shedding a badge is refused along with changing it.** A caller arriving unbadged at a service
  that tells its callers apart by badge has escaped being told apart, which is the same escape by a
  quieter route.
- **Two places demonstrated the hole as a feature.** The kernel's capability self-test derived a
  badged capability into a *different* badge and asserted the new one survived. `user/probe` did the
  same from raw ring 3, with the comment "the service sees the **new** badge, which is how a derived
  capability is distinguishable from its parent". It is not, and it must not be: what distinguishes
  a derived capability is its rights and its position under the parent, which the revocation in that
  very test already showed.
- **Both halves are gated, everywhere, because either alone is worthless.** Delegation under the
  same badge must work *and* a badge the holder chose must be refused. A kernel that refused every
  derivation would pass the second on its own — so that version was watched failing too, alongside
  the version with the rule deleted. Four levels caught each: a host test, the kernel self-test, the
  ring-3 boot gate, and the shell.
- **A check of my own that could not have worked**: the first version asked
  `badge & BADGE_DERIVED != 0`, and the two badges share bits — `0x1234_0000 & 0x5678_0000` is
  `0x1230_0000` — so it reported forgery on a machine where none had happened. Two badges cannot be
  told apart by masking, and there was no reason to think they could.
- The suite failed once on a UEFI boot timeout at 120 s with load average 8 and four external
  gitlab-runner processes taking 240% CPU; the same configuration passes standalone and the rerun
  was green at load average 11.6. Recorded because "it passed the second time" is not an
  explanation on its own.

### 2026-08-06 (RFC 0016 drafted — and two things found by writing it)

- **RFC 0016 is drafted**: a reply that can carry a capability, and the filesystem out of the
  nucleus. The two are one piece of work, which is what RFC 0015 steps 4 and 6 each concluded from
  opposite directions.
- **Badges are forgeable, today.** Any holder of a capability with `DERIVE` may derive another with
  a badge of its choosing — `derive_owned` sets the badge from its argument and checks only that the
  parent permits deriving, and `INVOKE`'s `DERIVE` passes it straight through from ring 3. Verified
  by running the derivation, not by reading it. Everything that uses a badge to say *who is calling*
  is unsound; the filesystem service keys per-caller state on one. The impact today is small because
  there is one interesting client, and that is luck. **The fix is RFC 0016 step 1 and is independent
  of the rest of it.**
- **The block service cannot write.** `bin/blkd` answers `block::READ` and `block::CAPACITY` and
  nothing else; RFC 0015's step 1 said "`READ` and `WRITE`", and only half was built. Nothing since
  has needed the other half — which means the **journal has never written to a device**. Every
  interruption test, host and machine, has stopped a store backed by an array. That is not wrong, and
  it is not the same claim as the one the journal exists to make.

### 2026-08-06 (RFC 0015 step 6 — a page cache, and a filesystem that stops holding its own bytes)

- **The cache was the smaller half.** Until this step every structure was read by indexing into one
  slice, which is only possible because the image happened to be memory. A filesystem on a *disk*
  has a device it can ask for one block at a time and somewhere to keep the answers — two different
  things. So there is a **`Store`** (how many blocks, read one, write one) and **`Pages`** (where a
  block is, right now), and exactly **one** implementation of "what an inode is" above them. Two
  readers, one for images and one for devices, would be two chances to disagree about the same bytes.
- **Write-back adds one ordering the journal did not need**: the log may not be cleared while a
  changed page is still dirty. It is the ordering an implementation would most plausibly leave out,
  because it goes missing at the moment everything looks finished — and recovery needs it too, or a
  survivable crash becomes a lost one on the *second* crash.
- **The interruption moved into the device.** Step 5 announced writes through a separate observer,
  one indirection away from the truth. The harness is now a `Store` that stops, so a trace is what
  the disk saw — which, with a cache in the way, is no longer what the filesystem asked for. That
  difference is what a cache is.
- **Watched failing four ways**: the log cleared while a page was dirty, the payload not on the
  device before the commit, a dirty page dropped on eviction instead of written, and recovery not
  flushed before clearing. The last is caught by exactly one test — the one written for it.
- **The one duplication this step forced is pinned by a test.** `Bitmap` holds the whole region at
  once, which `format` needs and a device cannot give; `Volume` walks it a page at a time, which a
  device forces. Two answers to "which block is free" is one block handed to two files, so they are
  asserted equal rather than trusted to stay in step.
- **What is not built, and why it is not a tail.** Lending a reader a capability to a cached frame
  cannot mean the whole cache — that exposes every other block in it, including other files' data.
  It has to be one frame, which must be pinned against eviction and revoked when the lending ends;
  and "when the lending ends" is a lifetime only the *owner of the cache* can see. That owner should
  be a service, which is the same conclusion step 4's debt reached from the other side. The two are
  one piece of work and are written up as the next RFC's shape.
- **`fs` is zero `unsafe` across 3,467 lines**, cache and journal and all.

### 2026-08-06 (RFC 0015 step 5 — a journal, and a harness that stops at every write)

- **Write-ahead, metadata only**, in one order: the payload into the log, the **commit block**, then
  the blocks to their homes, then the log cleared. Everything before the commit is provisional and
  everything after it is certain, and that instant is the only durability claim this filesystem
  makes.
- **"Acknowledged" had to be defined before anything could be tested.** "The call returned" is
  useless — a machine that stops does not return from anything. The definition is *the commit block
  was written*, which is an instant a harness can find in a trace, and it is what turns "every
  acknowledged operation is present" into a checkable sentence.
- **The harness stops at every write of every operation** and asserts the filesystem mounts and
  holds exactly the transactions that committed. Also with the writes **reordered** within each
  phase, since a device is entitled to, and with the **recovery itself** interrupted, since replay
  must be idempotent or the ordering is not sufficient.
- **The claim is not "before or after".** An operation of three transactions interrupted between two
  of them leaves the first and not the second, which is neither. The test builds a reference state
  for every prefix by running those transactions and no others. Asserting before-or-after would have
  passed a filesystem that applied half of the second one, and would have looked rigorous doing it.
- **Two things the RFC did not say, found by building it.** Beginning a transaction while one is
  committed destroys it — staging overwrites the payload the commit block checksums, so an
  *acknowledged* transaction silently stops existing. A crash cannot reach that; an error path can.
  And a block being **allocated** must have its data written before the commit that points an inode
  at it, or the file briefly reads whatever that block held for its previous owner: not a lost
  write, a disclosure.
- **A test that could not fail, again.** Moving the commit ahead of its payload changed nothing the
  first version of the ordering test could see — the payload is prepared in place, so the image came
  out byte-identical and only the order the writes were *issued* in differed. Rewritten to assert
  the whole shape of the trace. Sixth time.
- **`remove` retires a piece of scaffolding.** Step 4 had to manufacture a stale capability because
  nothing could produce one; removing a file now bumps a generation for real.
- **`fs` is still zero `unsafe`**, journal and all.

### 2026-08-06 (RFC 0015 step 4 — directories are capabilities, and there is no root)

- **`OPEN_AT` resolves one name inside a directory the caller holds**, and that is the only way to
  reach a file. No method takes a path. No capability names a root. What a program can reach is the
  transitive closure of what it was given, decided by whoever gave it rather than by a check at the
  moment of use.
- **The shell is handed `sub`, deliberately not the directory above it.** It opens `inner`. It
  cannot open `greeting` — same filesystem, one level up, a file the kernel itself reads at boot —
  and there is no check to forget, because it holds nothing that names the directory `greeting` is
  in. The refusal is the same one a name that exists nowhere gets.
- **A correction to the RFC's own text.** It said containment needs no check on `..`. Half right:
  the containment doesn't, but `..` still has to be *refused*, and refusing it with "no such name"
  is indistinguishable from not refusing it at all — `..` is not an entry in any directory this
  format writes, so a lookup would fail to find it and say the same thing. So there are two
  refusals: `BAD_NAME` for a name this system does not resolve, `NO_SUCH_NAME` for one that is not
  here. The distinction is safe because it describes the caller's own syntax; a name that exists
  *elsewhere* stays indistinguishable from one that exists nowhere.
- **A capability names an inode and a generation.** Nothing writes to this image, so nothing can go
  stale on its own — and the check would have gone untested until the step that introduces reuse,
  which is the step least able to afford finding out it does not work. The kernel manufactures one
  and the shell reports it resolving to nothing.
- **Watched failing four ways**, each on its own: the separator check deleted (a path becomes merely
  a missing name), the `..` check deleted (the same), the generation check deleted (`10 stale dir
  resolved — the generation was not checked`), and the shell handed the root instead of `sub` —
  where two gates fail by **succeeding**: `greeting: a file of 43 bytes, at slot 9`.
- **Two gates were vacuous when first written** and were rewritten before being believed. `open
  sub/inner` and `open ..` both printed "no such name" whether or not the guard existed. That is the
  fifth time in this project a test has been defeated by a redundant path.

### 2026-08-06 (RFC 0015 step 3 — a filesystem this kernel defined, in a machine)

- **The machine mounts a filesystem of its own format**, and the image is a member of the archive —
  so "beside the archive" is literal rather than a figure of speech. It reads `greeting` out of it,
  43 bytes that exist in no other file on the machine.
- **The same name is asserted absent from the archive.** Without that the test would pass for a
  mount that had quietly resolved through the old backend, and two filesystems would be
  indistinguishable from one read twice. It is the cheapest half of the check and the half that
  makes the other half mean anything.
- **Read-only, in that order, on purpose.** The format is proved by reading an image built somewhere
  else before anything is allowed to write one. A reader and a writer developed together agree with
  each other by construction, and a bug in the writer then looks exactly like a working system.
- **A block pointer off the end of the image reads as absent**, not as whatever is at that offset in
  whatever the image is embedded in — every block number came off a disk, and this one is inside a
  file inside an archive, so the bytes past it are real and belong to somebody else.
- **The negative test fails in two places**, which is what a step that spans the host and the machine
  should do: letting a read run past the size the inode declares fails the host test *and* the boot
  gate.

### 2026-08-06 (RFC 0015 step 2 — a format, and three negative tests that proved nothing)

- **The format is 1,003 lines and touches no kernel.** A superblock, a bitmap, inodes with a
  generation — RFC 0015's decision that a capability names an inode *and* a generation is in the
  structure rather than in a comment — and directories as fixed entries. `mkfs` builds an image and
  the format reads it back with the files intact.
- **The `unsafe` budget is zero and should stay there.** A disk is bytes somebody else wrote, which
  is the definition of untrusted input; this parser is what stands between a corrupted one and the
  rest of the system, and it is held to the standard `ustar` is.
- **A zeroed inode is free, and that falls out of an invariant rather than a special case.**
  `checksum` never returns zero, so a stored zero unambiguously means "never written" — which saves
  writing a valid free inode into every slot at format time, and makes corruption that zeroes the
  field read as *free* rather than as damaged. That loses a file rather than exposing one, which is
  the direction to fail in.
- **All three of the first negative tests passed, and that was the finding.** Removing the entry
  length clamp, removing the allocator's floor, and removing a range clause each changed nothing —
  not because the properties were false but because each was guarded twice. A test defeated by
  redundancy is a test that has never been shown to fail, and this is the fourth time this milestone
  that pattern has appeared. Each now targets the guard it names: the stored field rather than the
  accessor, a bitmap cleared through `set` so only the floor stands, and one superblock per clause.
  All three fail for their own reason now, and only their own.
- **The RFC's trigger, measured.** RFC 0015 said that if the format costs more than the journal, the
  decision to define a new one was wrong. Step 2 is 1,003 lines. That number is on the record so
  step 5 can be compared against it rather than remembered against it.

### 2026-08-06 (RFC 0015 step 1 — a block service, and a test that had been wrong twice)

- **Something can ask for a block now.** `bin/blkd` was a driver with no interface, which was right
  for RFC 0014 and was the first thing in the way of a filesystem. It answers `block::READ` over RFC
  0009's bulk path: the caller names memory it already holds, and the driver asks the kernel to fill
  it — the same `FILL` the filesystem's bulk path uses, which is the second thing that mechanism has
  turned out to be for.
- **The criterion is an oracle, not self-consistency.** The Makefile writes a string into sector zero
  of the disk the *domain* drives. The kernel checks that string came back and **cannot read that
  disk itself** — it drives the other one. A service that answered plausibly with the wrong bytes
  would fail.
- **A sector past the end is refused**, and the negative test for it proved nothing: with the
  driver's bounds check removed the *device* refuses instead, so the answer is the same. That is
  defence in depth rather than a gap, and it means the check is not independently tested — which is
  worth saying rather than leaving as an assumed pass. What is independently tested is the fill: a
  service claiming 512 bytes it never delivered fails the gate.
- **The IPC self-test had been wrong twice, and both times "load" was available.** `replies 9,
  correct 8` was recorded a few hours ago as seen once and not reproduced; it happened again, which
  is what that note existed for. It was the test's own bookkeeping — `REPLIES` incremented before
  the value was checked, `CORRECT` after, and the waiter woken by the first of the pair. The
  property is that *no reply was wrong*, which is one number. Asking it as `correct == replies`
  asked two counters that were never sampled together, and the gate's regular expression made the
  same mistake with a back-reference. Both now read `0 wrong`.

### 2026-08-06 (RFC 0015 accepted — and one decision that is told how to fail)

Accepted as written, with two of its four open questions decided and one handed to the RFC that
owns it.

- **The filesystem owns the page cache**, not the block service. A block service caches the wrong
  thing: it cannot tell a file from the journal, and would keep the log warm at the expense of data.
  The filesystem can, and it is also the side that hands out read-only capabilities to cached
  frames — which it can only do for memory it owns.
- **A `Directory` capability names an inode and a generation**, and deleting bumps the generation, so
  a stale capability resolves to nothing rather than to whatever took the slot. Not a new mechanism:
  `MemoryId` and `NotificationId` are both index-plus-generation for exactly this reason. The
  alternative — refusing to delete a directory somebody still holds — makes deletion depend on who
  is watching.
- **Deferred:** where path resolution begins for a program holding no `Directory` capability. Boot
  grants the first one, which is enough for every step; the general answer is a supervisor's, and
  process management owns that. Deciding it here would be this RFC ruling on something it does not
  have to.
- **Still open:** how large the cache may grow. Nothing in this system can say "this memory is
  reclaimable", and inventing that at step 6, where it is needed, beats guessing now.
- **The decision most likely to be wrong is told how to announce itself.** A new on-disk format,
  rather than ext2 or FAT, is the call this RFC is least sure of. The trigger is written into the
  document: if step 2 costs more than step 5 — if the *format* is larger than the *journal* — then
  the format was the work after all and this was wrong. Cheap to notice, and now not dependent on
  remembering to.

### 2026-08-06 (RFC 0014 step 6 — and a question whose answer was that it did not apply)

- **A driver names its own device.** One page of configuration space, read-only, and `1af4:1042`
  comes out of it with the kernel asked nothing. That page exists to be held only because PCIe made
  configuration space *memory*; RFC 0013 step 6 said the bus stays in the kernel because it was port
  I/O, and that sentence was true of the mechanism rather than of the design.
- **One number carries both halves of the decision.** The identity is reported only when a writable
  mapping of the same page was refused. Readable always, writable never — because a writable
  configuration page is a writable BAR, and an IOMMU governs what a device *reads*, not where it
  *answers*.
- **The open question was answered `nothing`, and that is the interesting part.** Acceptance left
  "how much of the command register is mediated" for step 6. The answer is none of it: the question
  assumed a driver would ask to become a bus master and the kernel would decide. It does not — the
  kernel already enables bus mastering after the device is reset, at the same point it grants the
  window that contains it. A system call whose only effect the kernel performs anyway, at a better
  time, has nothing to do. The delegable set ended up smaller than the RFC proposed, because the
  proposal carried an assumption rather than because the work was cut.
- **M8 is complete.** Two drivers, one set of register accessors, one virtqueue, one device model
  they can both be tested against, and configuration space reachable as memory and checked against
  the ports on every function of every bus. The kernel's `unsafe` fell twice along the way, which is
  the first time that number has moved downwards at all.

### 2026-08-06 (RFC 0014 step 5 — one virtqueue, and a byte that had been vanishing)

- **The protocol is one implementation now.** Descriptors, the rings, and the order the writes
  happen in live in a crate the kernel's driver and `bin/blkd` both compile. Nothing changed on
  either side, which was the criterion: 200 sectors, 2 requests, `BHASKIX-`, woken by the device.
  The kernel's `unsafe` fell 1112 → 1067, the second reduction in two steps.
- **Each ring is given twice** — the address the driver writes through, and the address the device
  is told. They are the same number without an IOMMU and different with one, and a driver that
  confused them would hand a device a physical address where a translated one was needed. Naming
  the parameter `address` *the device's* is as far as a type can go towards preventing that.
- **The ordering test is the one that could not be written before.** That the chain is published
  before the index which makes it visible is invisible in the finished memory: both writes have
  landed either way. The model records the order, and reversing the two writes fails exactly that
  test and no other.
- **A byte had been vanishing from the console, silently, and it looked like flakiness.** A shell
  test failed on a string that never appeared; the machine had printed `6  ignal rd`. The `s` was
  dropped by `serial::write_byte`, which gives up after a spin limit rather than hang — the right
  choice, made silently, and the emulated UART on a loaded host reaches that limit. It is counted
  now and reported at boot, and gated: **every other check reads that log, so this one decides
  whether they are reading all of it.**
- **A debug line had been shipping since RFC 0012 step 6.** `MARK msix readback` printed on every
  boot of every machine for days. Removed. Nothing failed because of it, which is why nobody saw it.
- **Two failures were investigated and only one was real.** A filesystem session was not always
  released after the placement measurement, and the shell was then refused with `BUSY` — that is
  fixed by verifying the release rather than sending it and hoping. The other, an IPC self-test
  reporting `replies 9, correct 8`, appeared once under load and not in four consecutive boot runs
  or the run after; it is written down here so the next occurrence is the second and not the first.

### 2026-08-06 (RFC 0014 step 4 — ECAM, and the oracle that earned its keep immediately)

- **Configuration space is memory now**, and the port pair stayed. Acceptance decided that on the
  grounds that a fallback nobody exercises is worth nothing but a fallback that is the *oracle* is
  tested by construction. It was: 65,536 functions read both ways on every boot, 8 present, none
  disagreeing. "The new mechanism found three devices" is not evidence that it found the right
  three, and there is no cheaper way to know than asking the old one.
- **The negative test found a real weakness in the same breath as proving the gate.** Shifting the
  device field one bit made the machine *stop booting* rather than report a disagreement: the
  address left the mapped window and faulted, because the accessor bounded the bus number and not
  the address the arithmetic produced. The bus check is sufficient only when the arithmetic is
  right, which is exactly the assumption worth not making. Bounded against the mapping now, and an
  in-range bus the arithmetic cannot place is counted as a disagreement — so the same break reports
  `135 of 65536 disagree` with the first address instead of hanging.
- **`MCFG` entries that describe nothing are skipped rather than believed** — buses running
  backwards, a base of zero — because an entry believed here becomes an address read later. Five
  host tests, including one that writes the expected addresses out by hand rather than recomputing
  them with the parser's own formula: a check that repeats the formula cannot catch an error in it.
- **Three shell checks had been failing under load and it was one bug.** Commands were typed on a
  fixed interval that assumed each finished inside it — true on an idle host, false on a busy one.
  Every line waits for its own echo now. The suite passed at load average 11.45, which is the load
  it had been failing at, so the fix is tested by the thing that was breaking it.

### 2026-08-06 (RFC 0014 step 3 — a model that can say no, and a process of mine that would not stop)

- **The harness models a device, not memory.** A register file answers with whatever was written,
  which is the one behaviour a real device does not have. Real devices *refuse* — a feature set they
  will not take, a vector they cannot give — and the refusals are what a driver gets wrong. A model
  that could not refuse would have tested the happy path and nothing else.
- **It runs the driver's own code.** `negotiate` and `take_vector` are what the kernel calls, not a
  copy: the register accessors made a `Bus` substitutable, so the same function reaches a model
  instead of a machine. Before that, the only way to learn what this driver did about a device that
  said no was to find a device that said no.
- **Each of the five tests was watched failing for its own reason.** Removing the feature read-back
  fails exactly one; removing the vector read-back fails exactly one; silently dropping
  `ACCESS_PLATFORM` fails exactly one. A test that fails when anything breaks is a test that has not
  been aimed.
- **The static harness bit immediately, as designed.** `Bus` dispatches statically, so a test double
  must be a static, so tests must serialise — and the first test to take the guard twice in one
  scope hung rather than failed, because the guards are shadowed rather than dropped. Split in two,
  with the reason written where the next person will hit it.
- **Two suite runs failed and neither was a flake.** The shell tests lost timing races, and the host
  turned out to be at load average **12.4 with no QEMU running**: an external CI runner, and — the
  part that was mine — a test binary from that spin-lock deadlock still burning 184% of a CPU
  thirty-two minutes later. `pkill cargo` had killed the driver and not the child. Killed it, load
  fell, suite green at 395. "Flaky" was available as an explanation both times and would have been
  wrong both times; the number that settled it was `uptime`.

### 2026-08-06 (RFC 0014 step 2 — the first time the unsafe budget went down)

- **Nothing changed, which was the criterion.** The boot line is identical: 180 sectors, 2 requests,
  status 0x0f, one wait and zero spins. A refactor of a working driver has no other honest test.
- **The kernel's `unsafe` count fell by forty-two lines**, and the budget was lowered to match. That
  is the first time this number has moved downwards. Forty-two blocks were making the same promise —
  *this address is a register* — over and over, at every access; there are two now, where the blocks
  are constructed, and the accesses are ordinary code. The promise did not weaken; it stopped being
  repeated in places where nobody could check it.
- **The compiler found the leftovers.** Three `unsafe` blocks became *unnecessary* and said so, and
  four hand-rolled accessors became dead. `read8` and `write16` survive, and it is worth knowing
  why: the request status byte is memory the device writes, and the queue notification is a
  doorbell — neither is a register in a block, and pretending otherwise would have been the refactor
  reaching past its own argument.
- **Twenty-seven accesses now go through offsets declared once**, with the layout checked at compile
  time. Those offsets previously existed in three places — this driver, `bin/blkd`, and RFC 0014's
  own example — with nothing checking they agreed.

### 2026-08-06 (RFC 0014 step 1 — a bug made unrepresentable)

- **The fix for bug 1 is that `Bus` has no 64-bit access.** A 64-bit register is two 32-bit
  accesses because the trait offers nothing else, so the mistake that left a device holding a queue
  it never looked at cannot be written down. Fixing it in one place would have been enough to be
  correct; leaving the operation out is what makes it stay correct.
- **One `unsafe` per block, not one per access.** Constructing an `Mmio` is the promise that an
  address is a register; reading and writing one is safe afterwards. `user/blkd` currently spends
  forty-two `unsafe` blocks on the same authority, declared forty-two times where it cannot be
  checked.
- **The layout check is a build failure, and it has been watched being one.** A test that asserts a
  layout at run time is an assertion that ships. `register_block!` checks overlap and overrun in a
  `const`, so a bad block fails to compile — which cannot be tested from inside the crate, because a
  test that fails to compile fails the build it is part of. Two fixture crates, excluded from the
  workspace, and the gate asserts they fail **and say why**: a build broken for an unrelated reason
  would otherwise read as the check working.
- **The test that would have caught the original bug now exists.** It asserts the *width and order*
  of every access, against a fake bus that records both — because a byte buffer cannot tell one
  eight-byte store from two four-byte ones, and that difference is the whole bug.
- **The fake bus takes a lock, rather than a comment asking for one.** `notify`'s test module said
  "one test, because the slots are a global" and then acquired a second that raced the first. This
  module shares one fake bus between four tests and serialises them.

### 2026-08-06 (RFC 0014 accepted — a framework whose case is an invoice)

Accepted as written, with three of its four open questions decided by acceptance.

- **Configuration space is read-only to a domain; BARs and the MSI-X table are never delegable.**
  The BAR reasoning is the load-bearing part: a BAR decides *where in physical address space a
  device answers*, and an IOMMU governs what a device reads rather than where it responds — so no
  amount of translation makes a writable BAR safe. This is the first thing in the project a
  capability may not name for a reason that is not about rights.
- **The kernel keeps its own block driver, and it shrinks.** It is how the machine reads its root
  filesystem before any domain exists; deleting it would mean a boot that depends on a domain to
  find the program that becomes that domain. It loses its hand-written virtqueue at step 5.
- **`register_block!` and `Mmio<T>` go in a new `device` crate**, below the kernel and above `arch`.
  Registers are not architecture-specific; the ordering primitives they compile to are.
- **The port-I/O path stays, because it is the oracle.** The question was whether a fallback nobody
  exercises is worth keeping. It is exercised: step 4's gate compares ECAM enumeration against the
  port-I/O path on the same machine, because "the new one found three devices" is not evidence that
  it found the right three. A fallback that is the thing the new path is checked against is tested
  by construction, which is a better reason to keep it than "some machine might need it".
- **Left open on purpose:** how much of the command register is mediated. Mediating it costs a
  system call per bus-master enable; granting it grants DMA without a window. Decided at step 6,
  against code, because the cost is measurable there and guessable here.

The RFC's case is not that the framework is elegant. It is that the second driver cost three bugs
the first driver had already learned and written down in comments — so the mechanism has to be
something other than a comment.

### 2026-08-06 (M7 status — where the service framework ended)

`architecture.md` §2 has said since M1 that a service can run inside the kernel or in a domain of
its own, chosen at build time, with the interface not knowing which. Nothing had ever tested it. M7
is that sentence made true, and the shape of what it cost.

**What is now the case.** Both services run in ring 3 and the nucleus runs none. A block driver runs
in a domain, brings up its own PCI device, reads a sector by DMA through a page table of its own,
and is woken by that device's interrupt. `services.toml` decides placement; `make test-placements`
boots all four combinations every build. The isolation costs about 5,000 cycles a round trip — the
same +48% for both services — and nothing at boot.

**What M7 did not do**, in the milestone section above rather than here, because a list of gaps is
worth more next to the claims than at the bottom of a changelog. In short: no supervisor, the
console's *driver* is still in the kernel, the domain filesystem is handed its image, DMA is granted
only where an IOMMU can contain it, and one request is in flight at a time.

**What the milestone found that nobody was looking for.** Four things, and every one of them was
already true before M7 started:

- A server could **reply to a thread it had never heard from** — a forged answer to a question
  somebody else had asked. Reachable from ring 3, because `Reply` is a system call and the caller
  was a number in a register.
- The kernel had **one address space**, since M5. With one user program at a time that is
  indistinguishable from keeping the right one, so nothing could tell; two services in domains on
  one CPU ran in each other's page table.
- A service thread that was **unpinned cost six times the latency** of the same code pinned. The
  comment explaining why it was unpinned was correct and the decision was still wrong.
- `verify_window` asserted **exactly one** context entry — the same property as "no strays" and a
  different number, which stopped being true the moment a second device translated.

None of the four was found by reading. Three were found by measuring or by adding a second of
something; the first was found by trying to move a service and discovering the boundary would not
let it.

**And one this update found.** `make test-host` named its packages, and when `ustar` and `vfs` moved
into a crate of their own their tests — including the archive mutation harness — quietly stopped
running. Twenty-two assertions were out of the suite for a day, and the suite said nothing, because
a crate that is not named is a crate that is not tested. It is `--workspace --exclude` now: one
entry, with a reason, instead of a list that has to be remembered.

### 2026-08-06 (the interrupt — RFC 0011 and RFC 0012 both stop being self-tests)

- **A driver with no privilege is woken by its own device.** The last poll is gone: the completion
  arrives as a notification, and the driver acknowledges to let the next one through. Everything RFC
  0011 built for delegation and everything RFC 0012 built for containment is now carrying a real
  request rather than a self-test — which is exactly what step 6 said it was for.
- **The split is the same one as everywhere else in this milestone.** *Which* MSI-X entry the queue
  uses is the driver's to say, in a register it holds. *What that entry contains* is the kernel's,
  because an MSI is a memory write of an arbitrary vector to an arbitrary CPU and a holder that
  could write its own entry would hold an interrupt-injection primitive. The domain chooses among
  what it was given and cannot widen it.
- **The negative test failed in two ways at once**, which is the useful kind. Without the bind, the
  driver never wakes *and* the stray-interrupt detector fires — the device's vector is programmed
  and nobody owns it. A delegation that half-happens is louder than one that never did.
- **`RFC 0011 step 5`'s note is now out of date in a good way.** It says a legacy line was used
  rather than an MSI-X entry "because MSI-X programming writes a real device's table and there is no
  spare device to write". There is one now.
- **One flake, recorded rather than explained away.** The tickless measurement failed once under
  full-suite load — 187 idle ticks against 278 busy — and passed on three solo runs and the next
  full run. It is a timing measurement on an emulator with one more domain in the machine than it
  had yesterday. Not chased, and written down so the next occurrence is the second and not the
  first.

### 2026-08-06 (the data path — three bugs, and the kernel's driver knew all three)

- **A program with no privilege read a disk by DMA.** It built a virtqueue in memory it holds,
  aimed the device with addresses the IOMMU translates back to that memory, kicked it, and got
  `BHASKIX-` off sector zero — bytes that are on its own image and on no other disk in the machine.
- **DMA authority is granted only when something can contain it.** With a unit, the domain gets a
  `DmaWindow` and reads its disk; without one it gets registers and no window, brings the device up
  and stops. A domain that could name physical addresses could point a device at the kernel, and a
  driver in a domain doing untranslated DMA is not a smaller trusted base — it is the same trusted
  base further away.
- **Two devices, two page tables, two domain ids, one unit.** Sharing the kernel's page table was
  one line and would have meant a delegated driver could reach whatever the kernel's device had
  mapped: contained from the kernel's *memory* and not from the kernel's *device*.
- **Three bugs, and the kernel's driver had learned every one of them already.**
  1. `queue_desc` written as one eight-byte store instead of two four-byte ones. The device took the
     queue and never looked at it. `virtio.rs` has a comment saying exactly this, three lines long,
     written when it cost somebody else the same afternoon.
  2. **Bus mastering never enabled.** A device that is not a bus master cannot write memory at all,
     so the rings stay empty and every request times out. `pci::enable`'s doc comment predicts the
     symptom word for word: *"which reads as a broken device rather than as a missing bit"*.
  3. A context entry added to a unit that was **already translating**, with no context-cache
     invalidation. Nothing had ever added a device to a live unit before, so nothing had ever needed
     it, and the entry sat correct in memory while the hardware used what it had cached.
  The lesson is not that the mistakes were subtle. It is that a driver written next to a working one
  should be read against it first, and the cost of not doing that was an afternoon of a device that
  said nothing at all.
- **No fault, no completion — and telling those apart is what solved it.** A device refused a page
  and a device that never asked look identical from outside. `iommu::fault()` distinguishes them,
  and it said "never asked", which ruled out every mapping theory at once.
- **The wait for the driver's report is now a wait for the report.** A fixed delay was too short on
  a loaded machine and too long on every boot, in that order.

### 2026-08-06 (RFC 0013 step 6 — a driver in ring 3, and the device it was given)

- **A program with no privilege brought up a PCI device.** It holds four capabilities: three pages
  of registers and one memory object. It maps them itself, resets the device, and walks the
  specification's handshake. A wild pointer in it faults in ring 3 and takes the driver down; the
  same mistake in a kernel driver takes the machine.
- **The bus stays in the kernel, and that is where the hardware puts the line.** Finding a device's
  structures means reading PCI configuration space, which is port I/O — a domain holding that would
  hold every device on the machine. So the kernel enumerates and the domain drives. That split was
  not chosen for tidiness; there is no way to hand over less.
- **Its own device, and the capacity proves it.** Two drivers on one device would race resets and
  interleave rings, so the test machine has two and the kernel takes the first. The domain's disk is
  one sector and the kernel's is 180 — a driver handed the wrong device reports a number nothing
  else here produces, which is a better check than any status bit.
- **"Untouched" was never true.** The first version asserted the device arrived with status zero,
  reasoning that nobody had driven it. It arrives with 11: the firmware probes disks before the
  kernel exists. Reported now rather than asserted, and the assertion moved to the thing only this
  device could have said.
- **The driver holds no console capability**, so it cannot print. Its findings go into the memory
  the kernel granted it, behind a marker word written last with a fence before it — because a page
  of zeroes reads exactly like a report of all-zeroes, which is what a driver that never ran would
  appear to have written.
- **The `/bin` count assertion fired a fourth time**, once per program this milestone added. It is
  the cheapest assertion in the repository and has now paid four times.

### 2026-08-05 (RFC 0013 step 6c — the last link, and a negative test that was lying)

- **A program in ring 3 is woken by a notification**, takes the badge, and finds nothing on the
  second look. That is the whole of what a driver in a domain needs for interrupts: its device
  raises one, the kernel masks the source and signals, and the driver wakes — holding no vector and
  no way to reach an interrupt controller.
- **The signal here comes from the kernel, not from a device, and that is deliberate.** An interrupt
  reaching a notification is already gated in the delegation self-test. What had never been
  exercised was the last link, and testing it against a real device interrupt would have meant a
  test that blocks until the machine happens to interrupt — a test of luck.
- **The negative test passed for two runs while testing nothing.** The edit that was supposed to
  remove the rights check never applied — a `replace` that matched nothing and said nothing, the
  same silent no-op that the em dash in `services.toml` caused earlier this session. Both times the
  check "passed" and both times that was the tell: a gate that stays green when you break the thing
  it guards is either wrong or was never broken. Applying the edit by line number rather than by
  text made the machine say `TOOK, which it should not`, which is what the gate is for.
- **`shell-test.sh` can keep its log now**, like `boot-test.sh`. Both print the serial output only
  on failure, which is right for a gate and useless when the question is what the machine actually
  said — and answering that question with `head -5` cost a wrong conclusion before the log existed.

### 2026-08-05 (RFC 0013 step 6b — a page of hardware, reached by capability)

- **A ring 3 program read the block device's status register.** Through a `Frame` capability and
  through nothing else: it cannot name a physical address, cannot ask for a neighbouring page, and
  is refused a writable mapping of the page it holds. The value is 15 — the device agreeing that a
  driver brought it up — which is a number only a mapping that reaches the hardware returns. Mapping
  one page over gives 1, and the gate says so.
- **The kernel is the only thing that can mint one, and that is the whole security argument.** A
  `Frame` capability *is* a physical address; a capability a domain could make would be permission
  to map any page, which is permission to be the kernel.
- **Uncached and write-through**, the same flags the kernel's own MMIO takes. A cached mapping of a
  device works on an emulator and then fails on hardware in the way that is hardest to diagnose.
- **One method, two kinds.** `ATTACH` takes `Memory` or `Frame`, because from the caller's side it
  is one question — let me see what I hold — and the difference is what it holds. `Backing::Direct`
  has been in the region map since M3 and had never been used from a user address space; tearing one
  down must not free the frame, because the frame is a device.
- **A test module said "one test, because the slots are a global", and had two.** The second drains
  the notification arena and asserts it comes back empty, which it does not while the first holds a
  slot. It failed once in a full suite run and passed on every re-run — the shape of a race. Fixed by
  making the rule enforceable rather than written down: both tests take a mutex. A comment asking
  people to keep to one test survives exactly until somebody adds a second.

### 2026-08-05 (RFC 0013 step 6a — the primitive a driver needs, before the driver)

- **A domain can now map memory it holds.** `ATTACH` on a `Memory` capability, into the address
  space that is *running* — asked of the hardware, like the fault handler, rather than of any
  bookkeeping. The address is the caller's choice; the frames are the object's. That asymmetry is
  the whole safety argument: naming an address is harmless because nothing about the address decides
  what memory arrives.
- **Two capabilities to one object is what makes the negative test mean anything.** The shell holds
  slot 3 writable and slot 4 read-only, naming the same memory. A program refused because it holds
  nothing has learned nothing about rights; refused because the capability it holds is weaker, it
  has. The reading right and the writing right are checked separately, and a caller asking for a
  writable mapping of read-only memory is refused rather than quietly handed a read-only one — it
  would otherwise find out by faulting, later, somewhere else.
- **Why this and not the driver.** Step 6 is the block driver in a domain, and a driver needs three
  things it cannot have yet: its rings mapped (this), its device registers mapped, and its
  interrupts delivered as a notification it can wait on. This is the first of the three, and it is
  the one every other domain will want as well. The remaining two are named rather than started, so
  the gap between "step 6" and "what is built" is a fact in this table and not an impression.

### 2026-08-05 (RFC 0013 step 5 — the numbers, and the two the first attempt got backwards)

- **A domain costs about 5,000 cycles a round trip, roughly +48%.** The same figure for both
  services, which is the part that makes it believable: console 10.0k → 15.2k, filesystem 11.3k →
  15.8k. On this emulated machine that is about 2 µs. It is a real cost and it is not a large one.
- **Shared memory still pays for itself, and by a lot.** 228 bytes: 10.3× faster than fifteen round
  trips in the nucleus, 7.3× in a domain. The domain's bulk path costs twice the nucleus's, because
  it copies into its own buffer and then makes a system call where the nucleus writes through the
  direct map — and it still beats the message path seven times over. RFC 0009 opened that gap for
  exactly this.
- **Boot time is the same either way**, ~7.6 s. The isolation is not paid for at startup.
- **The first attempt measured the wrong thing twice, and both times it reversed the answer.**
  Timing whole loops and dividing gave a *nucleus* filesystem four times slower than a domain one,
  varying 84k → 114k between runs of the same build. One unlucky preemption in two hundred dominates
  a mean. The minimum is the least-disturbed sample and the only figure that meant the same thing
  twice; the mean is printed beside it, and the gap between them *is* the scheduling noise.
- **The second reversal was a cold path timed against a warm one.** The bulk transfer ran first,
  faulting in its pages and touching every cold line, and came out nine times slower than the
  message path that followed it. Five passes with the minimum kept turned 0.11× into 10.25×.
- **Chasing the first reversal found a real six-fold cost.** The nucleus filesystem thread was
  unpinned — deliberately, with a comment saying it blocks on nothing but its own endpoint so it may
  run wherever there is room. True, and it turned every call into a wait for another CPU: 66k cycles
  against 11k pinned. The measurement is the only reason that line changed, and nothing else in the
  suite would ever have noticed.
- **What is asserted and what is only reported.** The round-trip *count* is asserted — one per
  operation, either placement, on any machine. The cycle figures are reported: a threshold would be
  a test of whichever machine CI runs on, green on a quiet builder and red on a busy one. The one
  timing that is asserted is that shared memory beats the message path by at least 2×, against a
  measured 7–10×, so it fails when the bulk path stops being one rather than when the builder is
  loaded. Watched failing by demanding 100×.

- **Two more things the measurement dislodged, neither of them a measurement.** Timing the
  filesystem claimed a session and never gave it back — `MAX_SESSIONS` is two, so the shell was
  refused with `BUSY` and had no filesystem at all. The service was behaving exactly as documented:
  it cannot know a caller has finished unless the caller says so. And the first-command race in the
  shell test, narrowed at M6-05 by waiting for the prompt, reopened once printing the prompt became
  a round trip to another address space — the first line is resent now until it echoes, rather than
  the delay being lengthened until it usually works.
- **An unsafe path written this session, found by reading it again.** When the address-space table
  was full, `install` dropped the space and then loaded it into `CR3` — freeing the page tables the
  CPU was about to translate through. It is leaked now instead, which is the lesser wrong: the
  mapping stays valid and every fault in it is refused. The table is eight entries against three in
  use.


### 2026-08-05 (RFC 0013 step 4 — the nucleus runs no service, and one address space was never enough)

- **Three unprivileged programs, and a nucleus with no service in it.** The shell asks the console
  service to print and the filesystem service to read, and neither of those is in the kernel. In the
  `console=domain vfs=domain` build the nucleus runs no service at all, which is the state RFC 0013
  was aiming at from the first paragraph.
- **The console capability is the point, not the console.** Holding it permits putting a character
  and taking a byte. The driver stays in the kernel — moving that out is step 6 — so what this buys
  is not a smaller kernel but a smaller blast radius, and that is the half worth having first.
- **The kernel had one address space, and had had one since M5.** Not by decision: `vm::install`
  kept a single `ACTIVE` space, the scheduler never touched `CR3`, and with one user program at a
  time that is indistinguishable from keeping the right one. Two services in their own domains,
  pinned to the same CPU, ran in *each other's page table*. Threads now carry their root and load it
  as they resume; the fault handler reads `CR3` rather than trusting bookkeeping, because
  bookkeeping is exactly what may be wrong when a fault is being handled.
- **The boot gates passed while the machine was broken.** All 42 of them, in the very configuration
  that faulted — because nothing in the boot self-tests runs two user programs at once. The shell
  test caught it. A suite that is green is evidence about what it exercises and about nothing else.
- **Every argument register is an output.** Both domain programs declared the system call's argument
  registers as inputs. The kernel writes the whole frame back, so that was a lie the compiler was
  entitled to believe: it kept a live value in `r8` across a `syscall` and then dereferenced the
  kernel's leftovers. The one program that got this right was the shell, which had been doing it
  correctly since M6-05 for no reason anybody wrote down.
- **The address-space gate is derived, not fixed.** It expects one space for the shell plus one per
  service in a domain, because a fixed number would be wrong in three of the four placements — and
  a gate that is wrong in three configurations gets deleted rather than fixed.
- **The `/bin` count assertion fired a third time**, once per program added. It is the cheapest
  test in the repo and has now earned its keep three times over.

### 2026-08-05 (RFC 0013 step 3 — the filesystem is a program now)

- **Every `fs::` method in the system is answered by a program with no privilege.** The shell, in
  ring 3, calls a filesystem that is also in ring 3. The kernel routes the message and owns neither
  end. That is the thing the whole design was for, and it took one context and one run loop rather
  than a rewrite — which is the only evidence that the trait was worth having.
- **The table decides, and the machine reports.** `kernel/build.rs` reads `services.toml` and emits
  a `cfg`, so one of the two paths compiles and the other does not; the boot line says what the
  kernel *did*, and the gate compares the two. Keeping those separate is the point: a report
  generated from the same file the build read would agree with it whatever the machine did.
- **Both placements boot, every build.** `make test-placements`, using the command-line override the
  RFC's question 3 resolved on — because a test that edited the table to test the table would not be
  testing it. Two boots and not two builds: a build proves it compiles, and the claim is that it
  *answers* the same either way.
- **The two placements disagreed about a refusal, and only the negative test saw it.** The nucleus
  checks the caller's capability before reading anything; the domain version read first and returned
  early on an empty read, so a caller with no right to that memory got "fine, nothing" where the
  nucleus said "not yours". Both placements were otherwise passing. This is exactly the divergence
  the design exists to prevent, and it appeared anyway within an hour of there being two placements.
- **A counter is not a witness.** The services gate keyed on the service's refusal counter, which a
  service in its own domain has no way to add to — it would have passed in one placement and failed
  in the other while the service behaved identically in both. It now reports what the test
  *observed*, which is what it should have done when there was only one placement.
- **The vfs listing test caught its own author.** It asserted exactly two programs in `/bin` and
  said in a comment that a third should fail rather than silently weaken it. Adding `bin/vfsd` made
  it fail. That is the second time this milestone an exact-count assertion earned its keep.
- **What step 3 did not do.** The console is still nucleus-only: a console in a domain needs a
  driver to talk to, which is step 6. And the domain filesystem is handed its image at entry rather
  than reading a device — real storage in a domain is step 6's problem too, and pretending otherwise
  here would have been a second unfinished thing hiding behind a finished one.

### 2026-08-05 (RFC 0013 step 3a — what moving one service out of the kernel found)

- **The filesystem is relocatable, and one function is why.** Everything in it was already
  placement-neutral except the bulk path, which read a caller's pages through the kernel's direct
  map. It now asks its context to do that (`Bulk::fill`): the direct map in the nucleus, a system
  call in a domain, and the service above cannot tell which. `check-placements.sh` proves the claim
  by building `services/vfs` with no kernel in the build.
- **A server could answer a question nobody asked it.** `Reply` took the caller from a register, and
  `deliver` writes a message into whichever thread it is given and wakes it. So any server — and
  `Reply` is a system call, so that includes a ring 3 one — could plant a message in an arbitrary
  thread's mailbox and wake it holding what looked like the reply it was waiting for. The badge
  could not be forged, so this could not fake an identity; it could fake an *answer*. The kernel now
  records who a thread received from and refuses a reply to anyone else.
- **The fix paid for itself twice.** Seven values did not fit in six registers, which is why the
  server side of `Recv` only ever delivered one argument register — and a service that packs a
  `Chunk` across four could therefore never have run in a domain. Not accepting the caller freed the
  register. `Request::caller` is gone from the trait entirely: a service that cannot name a caller
  cannot name the wrong one, which is a better property than checking the one it names.
- **Two checks in a row were not looking at what they claimed to.** The eleventh: the boot line said
  "was refused" whatever happened, so the gate passed while the check under it failed. Fixed, and
  then the twelfth immediately: the *failure* message contained the same sentence the gate greps
  for, so a failing check still matched. Two identical strings, one of which is evidence, is not two
  strings. Both were found by deliberately weakening the rule and re-running — neither by reading.
- **What is left of step 3.** The service is relocatable and not yet relocated: `services.toml` says
  `nucleus`, and those are two different claims the table makes separately on purpose. Still to do
  are the domain run loop's first real user (`service/domain` exists and compiles, nothing runs it
  yet), the system call behind `Bulk::fill` for a domain, the storage a domain filesystem reads
  from, and a program to be the domain. The boot line will say `vfs=domain` when that lands, and not
  before.

### 2026-08-05 (RFC 0013 step 2 — the table, and the thing that makes it true)

- **A table nobody enforces is a comment.** The claim is that a service moves between the nucleus
  and a domain by changing one line in `services.toml`. What makes that more than an aspiration is
  the check underneath it, and the check is deliberately not a lint: it reads the **resolved
  dependency graph**, because a service cannot name anything in the kernel without depending on the
  kernel, and a graph cannot be worked around by spelling something differently.
- **The console is compiled with no kernel present.** That build *is* the domain placement's
  compile. It is the strongest thing available here — a lint can be satisfied, a compile against a
  missing nucleus cannot.
- **Two fixtures, and both were watched failing before the gate was believed.** One service that
  calls into the kernel, one table wrong about itself. The first version of the malformed-table
  check reported one of its two faults and hid the other, because the duplicate-name test ran
  before the row had been judged on its own terms — a check that stops at the first thing it finds
  reports the shape of its own control flow rather than of the mistakes. That is the tenth check
  this milestone that was not looking at what it claimed to look at, and the third found by
  breaking something deliberately rather than by reading.
- **Extraction is what made the console's logic testable at all.** That a caller cannot put an
  escape sequence on the kernel's console was, until today, only checkable by booting a machine.
  It is now three host tests against fake ports, and both of the ones that assert behaviour were
  confirmed to fail when the behaviour was broken.
- **The filesystem did not move, and the table says so.** `relocatable = false`, in the file rather
  than in a comment: its bulk path reads a caller's pages through the direct map, so it cannot
  compile without the kernel. Recording that as a fact in the table is the difference between a
  step that is 90% done and one that is honest about which 10% is missing — deciding what a context
  hands over for bulk transfer *is* step 3, and this is the line that says why step 3 is not free.
- **The boot line is built from the table now**, so the machine and the file cannot quietly
  disagree. Confirmed by editing the table and watching the boot fail.

### 2026-08-05 (RFC 0013 step 1 — a refactor whose success is that nothing happened)

- **The boot output is identical.** That was the criterion, and it is the only one worth having for
  a step that moves two working services behind a trait: 19 requests, 1 caller refused, 5 entries,
  8 bytes, and the bulk path unchanged.
- **Three decisions are encoded rather than refactored.** `Reply` is a value and not a message,
  because the method and badge belong to the placement — a service that could set them could claim
  to be answering a different question, or claim an identity. `Context` carries the direct map base
  *explicitly*, which makes it the field to watch: it is the one a domain placement will not have,
  so a service reaching for it outside a bulk path has stopped being relocatable and is now visible
  doing so. And `Session` became public, because a service's state is part of its interface — the
  placement holds it, which is exactly why state hangs off the trait and a static would not move.
- **Dispatch is by message in the nucleus too.** Slower than a direct call, and the reason the two
  placements differ in placement rather than in shape. Acceptance decided this; the cost is on the
  record from M6-05 and M6-18.
- **The services' logic is now testable with no machine underneath**, which is most of the point of
  a trait: an unknown method returns a refusal rather than unwinding, and a caller with no badge is
  refused, both on the host.
- **The placement line is printed and gated, and is expected to change.** A line that can never
  change is a line worth distrusting — this milestone has now learned that nine times, so the gate
  went in with the line rather than after it.

### 2026-08-05 (RFC 0013 accepted — and a design document that described its own safeguards as existing)

- **Accepted with two of its four open questions decided.** The nucleus placement dispatches
  **through IPC** rather than by direct call: direct is faster and is also the door through which
  "no direct calls" erodes, and a design that starts with the fast path never gets the slow one
  back. The placement table is a **build-time** input, with a command-line override permitted for
  *tests only* — the QEMU run that forces every service into a domain is the mechanism this RFC
  exists for and must not need a second image, but a machine whose placements can be changed at
  boot has a security-relevant table outside the build.
- **Two stay open and are named**: a caller whose service died blocks for ever, and the fix needs a
  mechanism that does not exist — an endpoint that reports when the capability reaching it is
  revoked. And whether the console is honestly relocatable at all, which is a measurement rather
  than an argument.
- **Acceptance corrected `architecture.md`, which was not true.** The section on relocatable
  services described both safeguards — CI building both placements, a QEMU boot with everything in
  a domain — **in the present tense**, when there is no `Service` trait, no placement selection, and
  no service that has ever run outside the nucleus. That is the same failure as the "NO IOMMU"
  warning that printed unconditionally: a document describing its own safeguards as existing cannot
  tell the safe case from the dangerous one. It now says what is intended, what is specified, and
  which step each lands with.
- **The precondition is what made the RFC writable at all.** Until M6-18's bulk path, the two
  placements were identical *by accident* — four registers map into nobody, so "the same code runs
  either way" was true and meaningless.

### 2026-08-05 (M6 status — where the milestone actually ended)

> **One status section, deliberately.** Three accumulated here — one per time the question was
> asked — and they disagreed about the check counts and about which RFCs were finished. A file whose
> first line calls it the single source of truth cannot carry three answers to "where are we".
> Status is rewritten in place; the changelog below records *events*.

**Every M6 task is built. The unmet exit criterion is unchanged. What the milestone became is four
RFCs of protection work that were not in its scope, and a long lesson about tests.**

| Criterion | Status |
|---|---|
| Boot to a shell | ✅ Ring 3, holding two capabilities and nothing else |
| `ls` a real filesystem | ✅ Through IPC, from the ramdisk or from the block device |
| Load and run an ELF binary from disk | ✅ `root=disk` makes "from disk" literal |
| **The ELF loader survives 24 hours of fuzzing** | ❌ **Not met**, and unchanged since it was written down |

| RFC | Status |
|---|---|
| 0009 — shared memory | steps 1–6 (step 7 belongs to the IOMMU, done there) |
| 0010 — notifications | **COMPLETE** |
| 0011 — `IrqHandler` | **COMPLETE** |
| 0012 — IOMMU | steps 1–5 and 7; **step 6 built and switched off** |

**The result in one sentence**: a `virtio-blk` device that could read the kernel's memory at the
start of this milestone now reaches only the frames it was given — enforced by hardware,
demonstrated by taking them away and watching the disk stop, and delegable to a domain that holds
the authority for it and refused to one that does not.

**Two faults are open, with what is known and what is ruled out beside each.** Neither is a mystery
to guess at; both have a shorter list of candidates than they did.

| Open | Ruled out |
|---|---|
| ~~The block device's MSI is not delivered under interrupt remapping~~ **Closed 2026-08-11.** It was never an interrupt fault: enabling remapping cleared the translation-enable bit through a zeroed `GCMD` shadow, so the device's DMA was untranslated and its address space had no interrupt-remapping region in it. Every hypothesis chased for six days was a symptom | — |
| ~~A read through the delegated block service returns the wrong bytes, with remapping on~~ **Never a fault.** Recorded on 2026-08-11 and withdrawn the same day: the domain disk is regenerated by `boot-test.sh` before every run because a boot writes a filesystem to it, and the hand-rolled QEMU commands used to chase the MSI fault skipped that. Through the harness, remapping on, every check passes | — |
| ~~A reused device address keeps its translation~~ **Closed 2026-08-11.** The diagnosis was right and the missing piece was a test that could tell the fixed state from the broken one. `iommu_reuse_self_test` maps, writes, unmaps, re-maps the same address to a *different* object, and checks the **old** object's page is untouched; with the invalidation removed it fails exactly as M6-13 described. Reuse is on, exact-size | — |

**Nine checks this milestone were not looking at the thing they claimed to check.**

| Check | What it actually did |
|---|---|
| Frame-leak gate | Phantom ±16 frames, from reading two counters non-atomically |
| Fault harness | Blamed the kernel for QEMU's exclusive disk lock |
| Lock-order check | Ran before most of bring-up, so it verified the code preceding it |
| Soak harness | Four CPUs, structurally unable to see a single-CPU hang |
| `make test-host` | Never ran the arch crate — its fuzz harness had never executed |
| "NO IOMMU" warning | A constant, printed on machines with three of them |
| Window read-back | Located entries with the same function that placed them |
| Step 5's "reachable" | "No fault" passes on a mapping that points at nothing |
| Bulk path's refusal | An empty slot, then a wrong-kind capability — neither reached the check being claimed |

Four of those were written and caught in the same session. Every one was caught the same way:
**break the property deliberately and watch the gate.** None was caught by reading.

**And the machines see different bugs.** The IPC stall needed real parallelism — 14 failures in 40
on a two-socket host, never once locally. The single-processor boot hang needed *one* CPU — 7 in 24
there, 0 in 100 under the four-CPU soak written to catch that class. The newer-QEMU theory died on
the same borrowed machine. Before trusting a green run, ask which machine it was green on.

### 2026-08-05 (RFC 0011 step 6 — the last blocked step, and a precondition written as code)

- **The step RFC 0011 would not take until there was an IOMMU.** There is one, so it is taken: a
  domain can hold an interrupt, bind it to a notification it owns, and acknowledge it. That is the
  first moment a driver could run outside the kernel and still be told when its device wants
  attention.
- **What a holder does *not* get is the MSI-X table.** An MSI is a memory write of an arbitrary
  vector to an arbitrary CPU, so a holder able to program one holds an interrupt injection
  primitive obtained by writing two words. The kernel programs it and delegates the rest.
- **The precondition is enforced rather than remembered.** `irq::name` refuses unless something is
  translating. A comment saying "do not do this without an IOMMU" is a comment; a refusal is a
  property. On a machine with no unit the self-test skips and says why, and the gate takes that as
  a pass — the honest outcome for a machine where the step is not safe to take.
- **Three refusals are the substance, not the success path.** A legacy line cannot be delegated at
  all: it is shared, and a holder that never acknowledges masks a line other devices need — a
  domain wedging its own device is its problem, wedging somebody else's is the kernel's. A
  `Notification` capability is not authority over an interrupt however much of it is held. And
  `BIND` checks *both* capabilities, so an interrupt cannot be aimed at another domain's
  notification.
- **The test puts the interrupt back.** It hands the block device's real handler to a domain, and
  `BIND` is precisely the authority to redirect an interrupt — so without `rebind_notification` the
  driver would spend the rest of the boot on the timer, working and slower, which is the quiet
  degradation this milestone keeps finding.

### 2026-08-05 (RFC 0012 step 7 — delegation, and four bugs it dragged out)

- **A domain can now say what a device may reach, and only if it was given that authority.** A
  `DmaWindow` capability, `MAP` taking a `Memory` capability the caller already holds, and the
  device granted the weaker of the two capabilities' rights. The assertion is the *refusal* — that
  a domain holding both can map is the easy half; that one holding only the memory cannot is what
  makes delegation mean anything.
- **Device mappings had been 4096 times too high since step 5.** `shared`'s frame array holds
  physical *addresses* — `allocate_frame` multiplies before storing — and the doc comment said
  "frame numbers", so the caller multiplied again. Fixed, and the comment with it.
- **Step 5's test could not see that**, which is why it survived a step. It asserted "no fault was
  recorded", and a translation to an address that does not exist is dropped **silently** rather than
  refused. It now compares the bytes the device wrote against the sector it was asked for. *The
  third assertion this session that looked right and tested nothing.*
- **`Window` is `Copy`, so there were two of them.** `install` stored a copy: the driver mapped its
  rings through one allocator while the global one still believed those addresses free, and the
  delegated domain mapped its object **on top of the driver's descriptor ring** — same page tables,
  different idea of what was taken. One window now, and the addresses say so: driver
  `0x100000000`–`0x100004000`, domain `0x100005000`, object `0x100006000`.
- **The window lock was ranked innermost, and mapping allocates.** `map_page` takes the heap while
  holding it, so the heap was being acquired inside it. Ranked on what revocation does last rather
  than on what mapping does while held; the detector reported it on the first boot that mapped
  anything. `DmaWindow` is rank 2 now, outside the heap.
- **Device-address reuse is disabled, deliberately.** After map → unmap-with-invalidation → map of
  the same address, a device still reached it: the entry read back as zero and the access was not
  refused. Handing an address out again while hardware may still translate it is a revocation with
  a delay fuse. Bump-only until invalidation is proven; the reuse test is `#[ignore]`d with that
  reason rather than deleted, and `free` still records the extent.

### 2026-08-05 (RFC 0012 step 6 — built, and switched off on purpose)

- **RFC 0011's residual risk is not retired, and the code that would retire it is written.** A
  device raising an MSI it was never programmed to raise is answered by one field: the remapping
  entry's **source validation**, which checks that the device presenting a handle is the device the
  handle was issued to. Everything around it is built — the table, remappable lines and messages,
  and compatibility format blocked, because remapping alone routes what a device sends and blocking
  the old format is what stops it sending something else instead.
- **The I/O APIC works under it; the block device's message does not.** QEMU's trace shows the
  console's line remapped and delivered, and `msix_write_config enabled 1 masked 0` for the device
  followed by **no** `msix_notify` at all — it is not being rejected, it is not being sent.
- **Two real encoding bugs found on the way, both silent by construction.** The IRTE's destination
  sits at **bit 40**, not 32 — an xAPIC id is shifted within the destination field, exactly as the
  legacy message address does it. And the remappable message's **format bit is bit 4 with SHV at
  3**, which I had transposed. Either one produces an entry the unit accepts and never delivers: no
  fault, no message, and a driver that looks broken. Both are now host tests.
- **It ships off, and that is the point.** Enabling it costs the block driver its interrupt and
  leaves it running on the timer deadline — a machine that still works while quietly polling. That
  is the exact shape of degradation this milestone has caught five times in other people's checks,
  and introducing one deliberately to claim a step complete would be worse than the missing feature.
  `iommu=remap-irq` turns it on for whoever finishes it. **(Finished 2026-08-11: it works, and it
  is on by default. See the entries for that date — this bullet is what was true on the day.)**
- **What is left**: find why the device does not fire. Ruled out so far — `eim` on and off, SHV on
  and off, the destination and format bugs above. Worth trying on a newer QEMU than 4.2 before
  assuming the kernel is at fault; the IPC stall this session was found the same way.

### 2026-08-05 (RFC 0012 step 5 — where the two RFCs meet, and a test that had to be deleted)

- **Revocation now reaches the hardware.** `an object was reachable at 0x100000000, 1 mappings
  revoked, and the device was then refused it`. RFC 0009's `Memory` is frames, an owner and a
  revocation that must complete; RFC 0012 makes a device window one of the places such an object
  lives. A revoke that removed a page from every address space and left a device reaching it would
  be the same failure as leaving one CPU's TLB entry behind — gone from the tables, and still
  working.
- **Two deliberate-refusal tests could not coexist, and merging them was the fix.** A refused
  request never completes, so it leaves the virtqueue unusable: whichever of step 4's and step 5's
  tests ran second found a device that no longer answers, and reported *"nothing refused it"* about
  a machine where nothing had been **asked**. That is the same shape as every other blind spot this
  milestone — a result that is not about the property.
- **The merged test is the stronger one**, which is why deleting the other cost nothing. An address
  the device **had and lost** isolates the page tables from every other reason an access could fail;
  an address that was never mapped does not distinguish "the entry is absent" from "the width
  refused it" or "the device never asked".
- **A lock rank, and a cache that exists for the ranking rather than for speed.** `DmaWindow` sits
  inside `shared::ARENA`, because revoking takes the arena first and unmaps from the device
  afterwards. Invalidating an IOTLB happens while holding it — so the unit's register window is
  mapped **once** at bring-up and cached, because `mmio::map` reaches the heap, and the heap is the
  outermost lock here. Mapping per use would have been an inversion on every single unmap.
- **No budget raise this time**: arch 1032/1040, kernel 977/1000.

### 2026-08-05 (RFC 0012 step 4 — three things that were wrong, and none of them found by reading)

- **The device is handed `DevAddr`s now, and the numbers differ.** Driver frames at `0xf8aa000+`,
  device told `0x100000000+`. That difference is the proof translation is doing something: the
  addresses in every descriptor and queue register are ones only the unit can resolve.
- **The order had to change, not just the addresses.** A window names the device it translates for,
  so the requester id is needed before the window exists — hence a probe that finds the device
  without touching it. And translation has to be on before `DRIVER_OK`, because from that moment the
  device may read a ring, and a ring it cannot translate is a request that faults instead of
  completing.
- **A fault that was not ours.** `read 0xffdc000` — firmware memory. OVMF enumerates the disk to
  decide whether to boot from it and leaves it bus-mastering, so it DMAs with a stale ring the
  instant a unit starts translating. RFC 0012 predicts exactly this. Clearing bus mastering was not
  enough: `init` re-enabled it *before* resetting the device. `pci::enable_memory` and `pci::enable`
  are now separate — the BARs readable, then the reset, then the device may touch memory.
- **The negative test asserted the wrong thing and reported a protected machine as unprotected.**
  It required the read to fail, and printed *"the device READ AN ADDRESS IT WAS NOT GIVEN"* on a
  machine where the hardware had refused perfectly. virtio posts a completion for a request whose
  data write was refused — the ring entry is finished either way — so requiring an error tested the
  driver's plumbing rather than the protection. The assertion is the **fault record** now: device,
  address, direction. **The third time this session an assertion looked right and tested nothing,
  and the second where it would have condemned working code.**
- **`UNMAP` invalidates before returning**, which is why it cannot be a table write and a return:
  until the IOTLB is invalidated the device still translates through the entry just removed, so an
  early return tells the caller a page is unreachable while the hardware reaches it.

### 2026-08-05 (RFC 0012 step 3 — the gate that passed with the protection switched off)

- **Translation is on and a device is finally contained.** `5 driver frames and 0 reserved pages
  mapped, 0 refused, a read still works, no faults, device subject to it`. Before this a
  `virtio-blk` device could read the kernel's memory; now it reaches five frames it was given and
  nothing else, enforced by hardware.
- **The first version passed its own negative test.** I disabled the identity mapping entirely,
  enabled translation with the device's memory unmapped, and the disk kept working with zero faults.
  Translation genuinely *was* enabled — the device simply was not subject to it. QEMU routes a
  virtio device's DMA through the IOMMU only when `iommu_platform=on` **and** the driver negotiates
  `VIRTIO_F_ACCESS_PLATFORM`; neither was true, so the IOMMU protected nothing and every assertion
  passed anyway.
- **"Translation is enabled" and "this device is translated" are different claims**, and only the
  first was being checked. The driver now accepts `ACCESS_PLATFORM` whenever it is offered, the
  harness gives the device `disable-legacy=on,iommu_platform=on` — QEMU builds `virtio-blk-pci`
  transitional by default and a transitional device cannot carry that feature — and the boot line
  reports `device subject to it` as a separate fact. The same negative test now fails **four** gates.
- **The boot log used to state the wrong thing and then do the right one.** The DMA threat-model line
  was printed before the enable attempt, so it said "no translation yet" on a machine that was about
  to have some. It is printed afterwards now, and says what ended up true.
- **The refusal that QEMU cannot test.** An `RMRR` naming the kernel's memory would be firmware
  asking for a device to be given access to it. QEMU declares no reserved regions at all, so that
  path has no natural test here — four host tests cover the overlap arithmetic instead, including
  both inclusive boundaries, because a limit is the last byte and treating it as one-past lets a
  region ending on the kernel's first byte through.
- **Two `unsafe` budgets raised with the reason written down**: arch 980 → 1010 for the register
  window (`GCMD` cannot be read — a write sets the whole enable state — hence the shadow), and
  kernel 890 → 950 for the page-table walk and the enable sequence.

### 2026-08-05 (RFC 0012 step 2 — and a verification that verified itself)

- **The structures are built and nothing is enabled.** `iommu window 00:03.0 39-bit, 3 levels,
  nothing mapped, not programmed`. The page table is deliberately **empty** — default deny, so a
  device translated through this window could reach nothing at all. It is not shown to hardware
  until step 3 identity-maps the reserved regions, because enabling before that wedges the machines
  that need it most.
- **The encodings are arithmetic, and tested as arithmetic.** The hard part of an IOMMU is the bit
  layout of four table entries; the hard part to *test* is the hardware. Keeping them apart means
  the first is checked against the specification's numbers on a machine with no IOMMU, and only
  "was the right structure placed at the right address" needs the emulator.
- **My first read-back check was fake, and the negative test is the only reason I know.**
  `verify_window` located the entries with the same `context_index` that had written them. Corrupt
  that index and it writes at the wrong offset, reads at the wrong offset, and agrees — the gate
  passed a deliberately broken build. **A check that finds a thing using the same function that put
  it there cannot catch an error in that function.** It now recomputes the offsets from the
  requester id, with the duplication marked deliberate, and counts present context entries so a
  stray one is caught too. Same corruption now fails.
- **That is the sixth check this milestone that was not looking at the thing**, and the first I
  wrote myself in the same session I caught it. The rule that saved it is the project's own: every
  gate is negative-tested by deliberately breaking the property. Without that step this would have
  shipped as a verification that verified nothing, and it would have read convincingly in review.
- **The `unsafe` budget gate did its job**: 882 against 860, raised to 890 with the justification
  written in `kernel/Cargo.toml`. Three functions, all writing structures the *hardware* walks
  rather than the CPU, confined to one module so that "what can a device reach" has one answer in
  one place.

### 2026-08-05 (RFC 0012 step 1 — a warning that could not be wrong, and therefore said nothing)

- **`docs/memory.md` §5's degraded-mode line was a constant.** It printed "NO IOMMU: this device can
  reach all of physical memory" on every boot — including, as it turns out, on a machine with three
  of them. A warning that is printed unconditionally cannot distinguish the dangerous case from the
  safe one, which is the entire job of a warning. It was not wrong about *this* machine; it was
  incapable of being wrong about any.
- **The `DMAR` is now parsed, and nothing is programmed.** Step 1 is discovery only, so the line
  still reports that every device reaches all of memory — for the right reason, and only when true.
  On QEMU with `-device intel-iommu,intremap=on`: *1 unit found, not enabled; 39-bit addresses,
  interrupt remapping supported.* "not enabled" is asserted by the gate along with the rest, because
  a line claiming an IOMMU without it would read as protection the machine does not have.
- **The parser gets the treatment the RFC asks for.** A structure length of zero is the loop
  increment, so believing it is a hang rather than a crash — refused, with a test that says so. A
  register base that is zero or not page-aligned is dropped rather than recorded, because that
  address is dereferenced as hardware. More units than there is room for are **reported**, never
  silently truncated: a unit nobody recorded is a set of devices nobody is translating.
- **The discovery path is unreachable without an IOMMU to discover**, so `boot-test.sh` gained an
  `iommu` mode that supplies one. Without it every run would exercise only the absent case — which
  is precisely how the constant survived a milestone.
- **And the harness that was meant to catch this class was never running.** `make test-host` did not
  include `bhaskix-arch-x86-64`, so the MADT mutation harness — written to satisfy
  `docs/coding-style.md` §8 — had never executed in CI or in `make test`. It passes; it had simply
  never been asked. That is the fifth tooling blind spot this milestone, and the same shape as the
  other four: **the check was fine, and nothing was looking at it.**

### 2026-08-05 (why signals found no waiter — they always do)

- **The anomaly was not one.** `notify::SIGNALS == notify::UNWAITED` in the hung machine was written
  down as open. Instrumenting the signal side — a ring recording *which* notification each signal hit
  and what its waiter slot held — shows `n0->nobody n1->nobody` on **six boots out of six, healthy
  ones included**. `n0` is the console, `n1` the block driver.
- **Why it is normal.** The single waiter slot is claimed *inside* `wait_once`, which the driver
  reaches only after submitting the request and polling `completed()` once. The device finishes
  inside that window, so the interrupt arrives before anyone has registered. `signal` ORs its badge
  into `pending`, finds an empty waiter, and returns; the driver then takes the bits without ever
  sleeping. That is RFC 0010's ordering working — bits published before the waiter is looked for,
  so a waiter that has not arrived yet loses nothing. `1 waits, 0 woken by the clock` says the same
  thing from the driver's side: the wait returns immediately with a word already there.
- **A global counter could not answer a per-object question.** `UNWAITED` says how often, never
  which, and with two notifications signalling that was the entire question. The counter was not
  wrong; it was the wrong shape, and the fix was two more counters and a twelve-entry ring rather
  than more reasoning.
- **The lesson is about the note, not the kernel.** An "open, unexplained" line in this file is an
  instruction to the next session to go looking. Leaving one on a normal condition spends someone's
  time on a search with nothing at the end of it. **A recorded anomaly should be a measurement, not
  an impression.**

- **And a harness fault found while verifying it.** `shell-test.sh` typed at the machine as soon as
  the *banner* appeared. The banner is printed before the shell reaches its read; the prompt is
  printed from inside the loop that reads. Typing on the banner races that gap and the **first** line
  is the one that loses -- which is exactly how it failed, `'bhaskix$ help' never appeared` with every
  later command echoing correctly. It waits for the prompt now: 10 of 10 since, against a failure
  in a loaded suite run before.

### 2026-08-05 (RFC 0011 step 5 — a handler does not outlive its owner)

- **Destroying a domain is `RELEASE` for every handler it held.** `irq::release_owned_by` collects
  under the handler lock and releases outside it, like `ipc::destroy` — releasing masks a line
  through the chip and frees a vector through the allocator, both of which rank below it.
  `domain::destroy` calls it beside `shared::destroy_owned_by`, for the same reason: what a domain
  holds when it dies is otherwise unreachable and unexplainable.
- **`NO_DOMAIN` is not a spare number.** The console's and the block driver's handlers belong to the
  nucleus, and a teardown that swept them up because a recycled domain id happened to match would
  take the console away from a running machine.
- **The assertion is the re-claim, not the release.** A release that ran and leaked the vector, or
  left the claim standing, returns success exactly as loudly. So the test claims a spare line for a
  domain, checks a *second* claim is refused while it lives — otherwise "claimed again afterwards"
  proves nothing, because it was never unavailable — kills the domain, and claims it again. The
  vector count is asserted equal either side and printed, so a leak of one is visible rather than
  inferred.
- **Negative-tested by disabling the teardown**: `7 -> 8 -> 8 -> 8`, three failed checks and the
  gate red. A skip on a machine whose chip has no such input is a pass that says so in the log.
- **Ownership is recorded, not yet delegated.** `Source::delegable` — only message-signalled sources
  may be *given* to a domain — is a rule about a syscall boundary that does not exist until step 6,
  and is deliberately not enforced in `claim_for`. This is the half that can be built and tested
  without an IOMMU; step 6 remains blocked on RFC 0012.

### 2026-08-05 (a deadline that could never be reached)

- **One boot in four, on one CPU, stopped dead.** `fault-test` is the only harness that runs
  single-processor, and it boots six times: at 29% a boot, a clean sweep had about a **one in eight**
  chance. Every green run of the suite this milestone was luck, including the one that was pushed on.
- **Not a regression, and I said it was.** The first comparison was 0-of-8 against 2-of-8 and I read
  it as "I broke this". Twenty-four runs of each: **HEAD 7/24, the working tree 5/24** -- the same
  bug, present since the driver started waiting on interrupts.
- **The machine was asked where it was.** No output, so the QEMU monitor: `HLT=1`, and the halted
  `RIP` minus the KASLR slide symbolised to `sched::block_self`. Then the counters, read out of the
  hung guest at their symbol addresses: `DEFERRED_WAKES` empty, `DEFERRED_LOST` 0, and
  `notify::SIGNALS 2` against `notify::UNWAITED 2`. Nothing had been deferred and nothing lost --
  **no wake had been sent to a waiter at all.**
- **`await_completion` computed a deadline and then blocked past it.** `notify::wait_once` sleeps
  until it is signalled and no longer, so the deadline check at the top of the loop was unreachable.
  On one CPU the waiting thread is the only runnable one: the scheduler halts, the tick stops for
  being idle, and nothing is left that could re-evaluate anything. `time::wake_at` arms the clock
  before blocking, which the tickless path already honours -- it arms for the soonest outstanding
  timer. **RFC 0011 says a device that stops answering must not stop the kernel; the driver simply
  never armed the clock that made it true.**
- **What this does not fix.** All 24 runs now report `1 waits, 0 spins` and *no* timeout, so the
  deadline is not firing -- it is guaranteeing the CPU wakes and looks again. Why a signal found no
  waiter is still unexplained. The hang is gone; the oddity underneath it is written down rather
  than declared solved.
- **Two real windows closed on the way**, neither sufficient on its own: `restore_interrupts` then
  `cpu::halt` let an interrupt land between the `sti` and the `hlt` and be acted on before the CPU
  slept anyway (now the architectural `sti; hlt` pair), and deferred wakes are now drained before
  halting rather than only from a tick that an idle CPU has stopped.
- **The soak harness could not have found this.** It boots with four CPUs, where another thread
  keeps the machine alive and the fault is invisible: **0 in 100**. One CPU is a different machine.

### 2026-08-05 (the same window, everywhere it was)

- **The rendezvous fix named a pattern, so the pattern was worth hunting.** `mark_blocked`, then a
  check, then either `cancel_block` or `block_self`, leaves a thread *marked blocked and still
  running*. Where the check **consumes** what it was waiting for, a tick landing in that window is
  fatal: the wake is already spent and nothing will ever select the thread again.
- **`notify::wait` and `wait_once` had it exactly.** The look is `pending.swap(0)` -- it takes the
  bits. A thread preempted between taking them and clearing its own mark has swallowed the only
  signal that was coming; the block driver raises **one interrupt per request**, so there is no
  second one to save it. Same bug as the IPC stall, in a place with an atomic instead of a mailbox.
- **`sched::block_unless` is the shape that cannot go wrong.** The condition and the mark happen
  under one hold of the runqueue lock, which `preempt` reaches with `try_lock` and declines. Its
  one rule is written on it: **the closure must not take a lock**, because it runs under one.
- **The IPC fix had a smaller version of its own residual.** `mark_blocked` and
  `take_message_awake` were two lock acquisitions, so a tick between them stranded a thread whose
  message had arrived while it was awake -- the wake missed, then the mark, then nothing.
  `take_message_or_block` now decides all three outcomes under the single lock.
- **And the endpoint-destroyed paths, which is why `LIVE` exists.** Giving up needs to be decided
  in that same locked step, but `live()` takes the table lock and a table lock under a runqueue lock
  inverts against every path that takes them the other way. A lock-free mirror of the flag, written
  before the queues are cleared and before anyone is woken, lets the decision happen where it has
  to. **No `cancel_block` remains in `ipc.rs` or `notify.rs`.**
- **40 boots on the machine that used to fail 14 of 40.** `wait.rs` keeps the older shape and is
  correct with it: it enqueues *before* marking, so its check does not consume anything and a waker
  always finds it. `time.rs` likewise -- an expired deadline does not go away when it is read.

### 2026-08-05 (the rendezvous that stalled, and the machine that could see it)

- **A second machine changed the answer.** The same ISO that passes here failed the IPC self-test
  **fourteen times in forty** on a two-socket Xeon with real parallelism. Not a new bug: `7925e38`
  fails it 4 in 8. It has been in `main` for weeks, under a suite that runs every boot once, on a
  host whose QEMU is old enough that its four vCPUs rarely execute at the same instant.
- **What it was.** A receiver marks itself `Blocked` *before* checking its mailbox, so a wake
  arriving in the gap is not lost -- the rule M4-09 arrived at. That leaves a window where the
  thread is marked blocked **and still running**. Once it has taken the message out of its mailbox,
  the wake that would have rescued it is already spent, and `preempt` returns a thread to `Ready`
  only if it was `Running`. A tick landing between "take the message" and "clear the mark" switches
  the thread out blocked, holding the message, unwakeable: no future sender wakes a receiver it has
  already matched. `take_message_awake` now does both halves under one hold of the runqueue lock,
  which `preempt` reaches with `try_lock` and therefore declines to interrupt.
- **Four wrong theories, each killed by a counter.** Dropped handover: `dropped 0`. Lost wakeup:
  `wake missed 0`. Message stranded in a mailbox: `mailboxes 0` -- and *that* reading was itself
  wrong, sampled after teardown had freed the mailboxes, so it reported "no message anywhere" for a
  message that was in one at the time the test gave up. The trace ring settled it: `recv got` was
  the last thing that ever happened.
- **The lesson is about the harness, not the kernel.** Every gate here boots once. That is enough
  for a fault that is always there and worthless for one that depends on where a tick lands, and a
  one-in-three failure looks like a pass often enough to be believed. `tests/qemu/soak-test.sh`
  repeats a boot and reports how many passed -- deliberately at low concurrency, because
  oversubscribing the host serialises the guest's CPUs and hid this bug completely at 24 boots at
  once.
- **Fourth tooling blind spot this milestone**, after the frame-leak gate's phantom sixteen frames,
  the harness that blamed the kernel for QEMU's disk lock, and the lock check that ran before the
  code it was checking. The shape does not change: **the check was fine, and it was not looking at
  the thing.**

### 2026-08-04 (three lock inversions, and the check that was looking the wrong way)

- **`make test` failed after RFC 0009 step 5, on code that had nothing to do with it.** The
  lock-order detector reported `blocking on sched::QUEUES while holding virtio::DEVICE` — the block
  driver waiting for its interrupt **while holding the device lock**, which M6-07 shipped and every
  gate passed.
- **Worse than a rank inversion.** M4-08 established that `block_self` will not switch away from a
  thread holding a spinlock. So that "sleep" was a *spin with a lock held* — the worst of both, and
  invisible because the reply came back fast enough in an emulator.
- **The same mistake three times, in one milestone.** `virtio::read` waiting; `virtio::enable_interrupts`
  claiming an IRQ, creating a notification and mapping MSI-X; `irq::claim` mapping a register window.
  The pattern each time: **take the lock on the thing you own, then go and do everything else while
  still holding it.** It reads naturally and it is wrong every time, because everything else ranks
  lower. All three now hold the lock for exactly the state that needs protecting and do the work
  outside it — `claim` reserves its slot first, so exclusivity survives the gap.
- **The reason it shipped: `lock_ordering_self_test` ran at line 395**, before the I/O APIC, the
  block driver's interrupt path, the memory objects and the services. It verified the code that runs
  *before it*, which is not what anyone reading "0 violations" would take it to mean. There is now a
  second check at the end of bring-up, against a baseline, with its own boot gate.
- **This is the third tooling blind spot this milestone**, after the frame-leak gate's phantom
  sixteen frames and the harness that blamed the kernel for QEMU's disk lock. The shape is the same
  each time: **the check was fine, and it was not looking at the thing.**

### 2026-08-04 (RFC 0009 step 5 — a channel that cannot be double-fetched)

- **The ring lives in `abi` and touches no memory.** It computes where bytes go and whether a pair
  of indices can be believed; the loads and stores belong to whichever side owns the mapping, which
  is the side that can state the safety obligation. `abi`'s `unsafe` budget stays at zero, and the
  crate now says why it does *not* exempt `undocumented_unsafe_blocks` in tests the way the others
  do: an exemption there would be permission for something that must not appear.
- **The double-fetch rule is structural rather than documentary.** `Cursor` is constructed from
  *numbers*, never from a reference to the region, so by the time a caller holds one there is
  nothing left to re-read. RFC 0009's security section asked for "copy out before validating"; this
  makes writing it the other way impossible rather than discouraged.
- **Untrusted indices are refused, not clamped.** A clamped index is a number that looks usable and
  describes memory nobody wrote. What to do about a peer whose indices cannot both be true — drop
  it, log it, restart the channel — is the caller's policy, and this layer says only that the
  numbers are not believable.
- **Two test failures, and one of them was the test.** An empty `Run` named offset zero, which is
  inside the header where the *other side's index* lives; nothing copies zero bytes there today, and
  that is not a property of the type. And I asserted that a wrapped pair (`head = 0`,
  `tail = u64::MAX`) should be refused — **a misreading of my own design**: free-running indices
  wrap, the subtraction wraps with them, and that pair is one outstanding byte. The test now asserts
  it is accepted, which documents the seam.
- **The test worth keeping** is the exhaustive one: every index and length a ring of that size can
  produce, asserting no run ever names a byte outside the data area. An off-by-one there writes into
  the peer's index, which is the one bug in this module that would be a security problem rather than
  a corruption.

### 2026-08-04 (RFC 0009 step 4 — two domains, one object)

- **Sharing is real and checked through the page tables.** Two address spaces, two *different*
  virtual addresses, resolving to the same physical frames. Asserted with `translate()` rather than
  inferred from the mapping calls returning `Ok` — the second is a statement about this kernel's
  control flow, the first about the hardware's.
- **The giver hands over a `READ` derivation, and monotonicity makes that a ceiling.** There is no
  path from the recipient's capability back to write access, and the test asserts the rights are
  exactly `READ` rather than merely that a capability arrived.
- **A `Memory` capability's identity carries the object's generation**, so a capability outliving its
  object names nothing rather than naming whatever took the slot.
- **`revoke_capability` does mappings first, then the subtree** — the ordering *is* the design.
  Capabilities first would leave a window where the capability is dead and the memory is still
  mapped, which is the delay fuse `security.md` §2 rule 3 forbids.
- **What this completes, and what it does not.** Step 3 could not show the RFC's "B faults after A
  revokes" because B was not running. Step 4 shows the whole chain up to the fault: B had the frames,
  the capability was revoked, B's page tables no longer resolve. **The fault itself still needs a
  second ring 3 domain**, which is step 6's territory — and is recorded as outstanding rather than
  described as done.

### 2026-08-04 (RFC 0009 step 3 — revocation that means something)

- **After `revoke` returns, the pages are gone from the page tables.** Not from the region map — from
  the tables, because tables are what grant access. `security.md` §2 rule 3 says revocation is
  transitive and immediate; for memory that has to include the mappings, since **a revoked capability
  whose pages are still mapped is not revoked, it is renamed.**
- **A mapping records a page-table root, not a reference to an `AddressSpace`.** A reference would be
  a pointer this arena cannot keep valid. The consequence is that the region map outlives the
  mapping, which is harmless bookkeeping — and would not have been, but for the next item.
- **A hole found by reading, not by a test.** `vm::handle_fault` would have serviced a fault on a
  `Backing::Shared` region by allocating a *fresh* frame — so a revoked mapping would silently
  reappear as blank memory at the same address. Worse than either keeping it or refusing it. Shared
  regions are mapped eagerly and never demand-paged, so a fault on one means the pages were taken
  away; it is refused now, with the reasoning at the arm.
- **The ninth mapping is refused before anything is mapped.** A mapping that succeeded and could not
  then be recorded would be one revocation cannot find, which is the single failure this design
  exists to prevent. `MAX_MAPPINGS` is eight because the walk must complete without allocating.
- **A TLB shootdown per page, before returning.** An entry surviving in one CPU's TLB is a mapping
  that is gone from the tables and still works — a revocation with a delay fuse, which is the thing
  rule 3 forbids.
- **What step 3 does not yet demonstrate:** the RFC's "B faults after A revokes" needs a second
  domain with the region mapped and running, which is step 4. What is asserted instead is the
  mechanism underneath it — `translate()` returns nothing after revocation — which is the property
  the fault would be evidence *of*.

### 2026-08-04 (a harness that blamed the kernel for its own contention)

- **`make test` failed at fault injection, and the kernel was not at fault.** The message was
  `missing: 'EXCEPTION: divide error (#DE)'`, which reads as an exception handler that did not
  report — and sent one investigation straight at the exception path. The actual cause: **QEMU takes
  an exclusive write lock on a disk image by default**, and M6-06 attached `build/initrd.tar` to
  every harness. Two runs overlapping by a second — which is every `make test` on a loaded host —
  and the second starts with no disk.
- **Demonstrated rather than assumed.** A second QEMU on the same writable image prints
  `Failed to get "write" lock`; the same with `readonly=on` runs. The image is now attached read-only
  everywhere, which is also more honest: the kernel only ever reads it.
- **The harness now says why a run ended.** `fault-test.sh`'s waiter returns whether it found what it
  was looking for, timed out, or outlived the machine, and reports that *before* listing what the log
  did not contain. A timeout on a loaded host and a broken exception handler are not the same failure
  and must not print the same way.
- **`boot-test.sh` stops after one accurate line instead of thirty misleading ones.** If the machine
  never finished booting, every assertion below fails for the same reason; that wall of red has twice
  been mistaken for a catastrophic regression. It now reports the boot failure, shows how far it got,
  and exits.
- **The lesson, since this is the second time this project has been misled by its own tooling:** a
  test that cannot distinguish "the thing under test is broken" from "the test could not run" will
  eventually be believed about the wrong one.

### 2026-08-04 (M6-08 — RFC 0009 steps 1 and 2)

- **A `Memory` object exists**: frames, a length, an owner. Charged to the owner's envelope when it
  is made and released when it goes, all-or-nothing on every failing path — a half-made object is
  one somebody has to find and clean up, and that somebody is nobody.
- **`ObjectKind::Untyped` is deleted**, which is what accepting RFC 0009 decided. The reasoning sits
  where the type is defined rather than only in this file: accounting here is a quota, not an exact
  partition of physical memory, and that was chosen rather than discovered.
- **`Backing::Shared` lets an address space borrow frames it does not own.** Every release path
  already checks for `Backing::Anonymous` rather than "not reserved", so a shared region is skipped
  **by construction** rather than by a branch someone has to remember. `EXECUTE` is refused
  outright — revocation unmaps while the other side is running, and a receiver whose *code* vanishes
  faults at an instruction that no longer exists.
- **The lock-rank checker caught a real inversion on the first boot.** `create` and `destroy` called
  the frame allocator and the domain table *while holding their own arena*, both lower-ranked. The
  fix was not to renumber the ranks but to stop holding the arena across those calls, so it is now a
  genuine leaf — and the declaration says so, and says the checker found it.
- **A test that could not fail, for the third time in this project.** The teardown invariant was
  first asserted as "fewer than four extra frames after destroying the address space", which passes
  whether or not the shared frames were wrongly freed, because teardown also returns the page tables
  it built. It is now exact: the frame count *before the address space exists* must equal the count
  after it is destroyed — "it returned exactly what it took, and nothing that was not its". The
  pattern each time has been the same: an assertion satisfied by both the correct and the broken
  world.

### 2026-08-04 (M6-07 — RFC 0011 steps 1–4, and a driver that stopped polling)

- **`virtio-blk` waits on an interrupt: 1 wait, 0 spins, 1 interrupt per request.** Before this it
  spun on the used ring for the duration of every request. The gate asserts the *pair* of counters
  rather than a duration, because "0 spins" is a claim a timing measurement on an emulator could
  not make.
- **There is one registry for all 256 vectors**, and the serial line's is now *allocated* rather
  than named: `input::SERIAL_VECTOR` is gone, and its absence is the point. Five constants across
  four files became one table that the boot log prints, so a collision is a boot failure rather
  than a machine behaving strangely.
- **The delivery path is three steps and nothing else**: mask the source, signal a notification,
  acknowledge the controller. `input.rs` drains the UART and *then* acknowledges — the rule
  `driver-model.md` §2 gained at RFC 0011's acceptance, demonstrated by the kernel's own first
  client rather than left for the first driver author to get wrong.
- **RFC 0010's `Notification` landed with it**, because step 3 binds one. One waiter, refused rather
  than queued; signal takes no lock, which is what lets an interrupt handler call it.
  `notify::wait_once` was added for the block driver: it blocks *once*, so a caller can arm its own
  deadline and still find out whether it was the device or the clock that woke it. That is not the
  timeout RFC 0008 leaves unresolved — it is the smaller thing that lets a caller build one.
- **The lock-rank checker earned its keep on the first boot.** `irq::HANDLERS` and `vectors::TABLE`
  were given the same rank, and claiming a source takes one then the other. Two locks of one rank
  have no declared order and can close a cycle exactly as an inversion can; the detector said so
  before anything deadlocked.
- **Two things this cannot yet catch, recorded rather than implied.** Acknowledging *before*
  draining is a rule with no gate behind it: both of this kernel's sources are edge-triggered, so
  the loss window needs a second interrupt inside it to be observable. And not masking at all is
  invisible for the same reason — a level-triggered source would storm, and neither of ours is one.
  The first level-triggered device will make both testable.
- **Step 5 (domain teardown) and step 6 (delegation) are not done.** Six is blocked on RFC 0012's
  implementation, as its acceptance note says.

### 2026-08-04 (RFC 0012 accepted — and a roadmap phase moved with it)

- **The IOMMU design is decided, and the roadmap changed to match.** Discovery, per-device domains
  and strict mapping move from Phase 3 to **Phase 2**; interrupt remapping, nested translation and
  AMD-Vi stay in Phase 3. This is the first RFC in the project to reorder planned work as part of
  its acceptance, which is why the phase change is recorded in the RFC's own status line as well as
  here.
- **Acceptance decides a design; it does not deliver a mitigation, and `security.md` now says so.**
  §1's threat table has listed "IOMMU-enforced DMA windows" against **T3** and **T4** since Phase 0.
  There is still no code. The table now carries a note saying the mitigations are *designed and not
  yet delivered*, quoting the boot line that admits it and pointing at the gate that asserts the
  line. **The note comes out when the code lands and not before** — a mitigation column is a claim,
  and a claim with nothing behind it is the most expensive documentation a security project can
  carry.
- **Four unresolved questions taken as proposed**: one window per device; in-nucleus drivers get
  their own windows and the cost is measured rather than assumed; no ATS or device page faults; and
  a machine with no IOMMU runs everything except a domain-hosted driver. Questions 3 and 4 stay
  open, and 3 belongs to whichever RFC defines the device object.
- **VT-d first is accepted with its cost**: an AMD machine runs degraded until AMD-Vi lands, which
  is hardware many contributors will have. The reason is testability rather than preference — QEMU
  emulates VT-d, and a design CI cannot exercise is one that will be wrong unnoticed.
- **RFC 0011's step 6 is no longer blocked on a decision**; it is blocked on this RFC's
  implementation, which is a different and smaller thing to be waiting for.
- **Three documents changed.** `memory.md` §5 records the two revisions the RFC makes to its own
  ten-month-old sketch — the capability does not live inside the window, and `DmaBuffer` is RFC
  0009's `Memory` — and admits that the "attestation log" half of its degraded-mode sentence names
  something that does not exist. `driver-model.md` §5's "default deny" gains the distinction between
  a framework's promise and a hardware guarantee. `roadmap.md` carries the split.

### 2026-08-04 (RFC 0011 accepted — interrupts get an owner)

- **Interrupt authority is decided.** `IrqControl` hands out `IrqHandler` capabilities, one per
  source, exclusively; the kernel's path becomes mask → signal a notification → acknowledge.
- **Acceptance narrows what a future contributor may do, in three ways worth naming.** A domain may
  claim only MSI-X sources — legacy shared `INTx` stays in the nucleus, because a holder that never
  acknowledges masks a line other devices need. MSI-X programming is never delegated. And unresolved
  questions 3 and 4 are taken as proposed: a source whose holder died is masked permanently and
  reported, and MSI-X is the only message-signalled form supported.
- **One constraint now binds a component that does not exist yet**, which is why it was worth
  writing down at acceptance rather than at implementation: **a device's MSI-X table pages must
  never be inside an `MmioCapability` given to a domain.** Programming an MSI is a device write of
  an arbitrary vector to an arbitrary CPU. That sentence is now in `driver-model.md` §3, where
  whatever hands out MMIO capabilities will be read.
- **Steps 1–4 are unblocked and pay for themselves.** They retire five hand-routed vector constants
  in four files — the timer, both IPIs and the serial line — for a real allocator, turning a
  collision from a machine behaving strangely into a boot failure, and they let `virtio-blk` stop
  burning a CPU per request. **Step 6, delegation to a domain, stays blocked on RFC 0012.**
  Accepting this does not make a user-mode driver safe, and the RFC's own table says so.
- **Three documents changed.** `driver-model.md` §1 renames `IrqCapability` to `IrqHandler` and
  records the MSI-X-only rule; §2 gains the step it was missing — *the source is masked before it is
  signalled* — and the driver-author rule that follows from it, **drain the device before
  acknowledging**, because an edge raised while masked is lost and that bug presents as a hang under
  load and nothing in testing. `scheduler.md` §4 gains the RT wake-up source its 50 µs budget was
  really written for: a driver woken by its device, measured from inside the handler.
- **No testing debt.** Everything in the plan concerns code that does not exist; the one item
  touching existing machinery is the vector allocator, which is step 1 rather than an obligation.

### 2026-08-04 (RFC 0010 accepted — A3 is now answered in full)

- **Notifications are decided**, and with RFC 0009 that completes the answer RFC 0008 gave to **A3**
  fifteen months of milestones ago: *synchronous rendezvous is the primitive, and async is built
  above it from shared memory plus a notification capability.* Both halves are now accepted
  decisions rather than promises.
- **What acceptance locks in, beyond the object: at most one waiter, refused rather than queued.**
  The RFC names this as the decision most likely to be argued with, so it is worth repeating here.
  It is the divergence from seL4 — which queues waiters — and everything else rests on it: one
  waiter is what keeps the signal path lock-free, and a lock-free signal path is what lets an
  interrupt handler call it. Adding a queue later is a `try_lock` plus a deferred-wake fallback,
  which is machinery M6-04 already built. A known change, not a corner painted into.
- **No testing debt**, as with RFC 0009 — everything in the plan concerns code that does not exist,
  and the fuzz-target answer is a reasoned "none". Two of its negative tests describe bugs this
  project has already made and fixed in `input.rs`, which is why they are written down.
- **A cross-reference error, caught at acceptance.** The impact section cited `driver-model.md` §5
  where it meant §2. Fixed rather than preserved: a wrong pointer is not part of an argument, and
  the immutability rule protects the reasoning, not the typos.
- **Two documents changed.** `architecture.md` §3 adds a notification to the list of things a
  capability can name, with what it is and why it is easy to overlook. `driver-model.md` §2's
  "signal the waiting driver task" stops being a phrase and names the mechanism — while saying
  plainly that *who may receive an interrupt* is RFC 0011 and still a draft.

### 2026-08-04 (RFC 0009 accepted — and a fork closed with it)

- **Shared memory is decided.** A `Memory` object a capability names, mapped into the holder's *own*
  address space, unmapped from everywhere before a `revoke` returns.
- **The fork is closed in the direction the RFC proposed: `Untyped` memory does not exist.** The RFC
  marked that question "decided by the project owner, before implementation starts", and acceptance
  is that decision. Kernel memory is not retyped from untyped capabilities by userspace; a `Memory`
  object comes out of a domain's `ResourceEnvelope`. **This is a deliberate divergence from the seL4
  lineage the rest of the design follows**, and the cost is accepted with it: accounting becomes a
  quota rather than an exact partition of physical memory. `ObjectKind::Untyped` is deleted when the
  code lands.
- **No testing debt on acceptance**, unlike RFC 0008. Everything in RFC 0009's plan is about code
  that does not exist yet, and its fuzz-target answer is an explicit "none, and here is why" — the
  offsets arrive in registers and are range-checked, so there is no structure being parsed. The one
  item that touches existing machinery is a note to point the frame-leak gate at shared regions when
  they land, which is now written into `memory.md` §3 rather than left in an RFC nobody rereads.
- **Four documents changed.** `memory.md` §3 gains the two invariants that come with `Shared` backing
  — the frames belong to the object, and revocation unmaps before it returns. `memory.md` §5 records
  that a `DmaCapability` names a `Memory` object, and that a device-visible one is kernel-only until
  there is an IOMMU. `architecture.md` §2 notes that today's services are placement-independent *by
  accident*, because there is nothing to map either way, and that shared memory is what makes the
  both-placements CI job stop being a formality. `roadmap.md` Phase 2 gains the item, placed before
  the service framework — a framework whose bulk paths move sixteen bytes per round trip is one
  nobody will measure twice.
- **Questions 2–5 stay open** and belong to the implementation: whether an object must be physically
  contiguous, `MAX_MAPPINGS`, and whether a mapping may be resized. Question 3 was already answered
  by RFC 0010 existing.

### 2026-08-04 (RFC 0008 accepted — and the commitment that came with it)

- **A2, A3 and A4 are decided.** Capability invocation with six syscall kinds; synchronous
  rendezvous as the IPC primitive; a capability-shaped native ABI. Thirteen milestones were built
  against the recommendation before the verdict, and **no code changed on acceptance** — which is
  the outcome waiting would also have produced, more slowly and with less evidence. The note in
  M5-03's entry saying this was a risk stays, struck through, because a risk that is only recorded
  when it turns out badly is a record that flatters the project.
- **Accepting an RFC accepts its testing plan.** RFC 0008's said: *"a fuzz target on syscall
  argument decoding, before user mode can be reached by anything untrusted."* Untrusted code has
  been reaching it since M6-05 and no such target existed. It does now, and it asserts something
  stronger than "no panic": that **no frame a caller can write produces authority** — every
  capability in the CSpace after an arbitrary system call still names the object it named before,
  with rights within what was granted.
- **The first version of that harness could not fail.** It seeded the domain with `Rights::ALL`, so
  "nothing can widen its rights" was a statement about a set with nothing above it. Seeded with
  three rights instead, and negative-tested by removing the monotonicity check in `cap::derive_owned`
  — caught at seed 932, slot 6, `Rights(43)` outside `Rights(49)`.
- **Two of the RFC's five unresolved questions were answered by implementation, not by argument**,
  and the RFC is not edited to claim it foresaw them:

  | Question | Answer, and where it came from |
  |---|---|
  | Q2 — how large is a register-carried message? | **Four registers.** RFC 0009 explains what happens to anything larger; M6-05 measured the cost at sixteen bytes per round trip |
  | Q5 — how many capability slots per CSpace, and is it fixed? | **64, fixed.** `cap::CSPACE_SLOTS`; fixed keeps allocation off the invocation path, as the RFC hoped |
  | Q1 — does `Recv` need a timeout? | Still open. Nothing has hung yet, which is not evidence |
  | Q3 — does `Call` donate the sender's slice? | Still open. Not implemented |
  | Q4 — how does telemetry name a capability? | Still open. There is no telemetry plane |

- **Three design documents changed, as the RFC's impact table said they would.**
  `architecture.md` §3 gains the six kinds and why there is no numbered table; `security.md` §2's
  four rules become a table of named functions and the tests that check them — each of which has
  been shown to fail; `roadmap.md` records that a native program links no libc, with M6-05's shell
  as the demonstration.

### 2026-08-04 (M6 — every task built, and one exit criterion that is not met)

**M6's tasks are all done. Its exit criteria are not all met, and the gap is worth stating in one
place rather than leaving to be discovered.**

| Criterion | Status |
|---|---|
| Boot to a shell | ✅ A user-mode shell in ring 3, holding two capabilities |
| `ls` a real filesystem | ✅ Through IPC, from the ramdisk or from the block device |
| Load and run an ELF binary from disk | ✅ `root=disk` makes "from disk" literal |
| **The ELF loader survives 24 hours of fuzzing** | ❌ **Not met.** 20 million mutated inputs per parser, clean. See below |

The fuzzing criterion is met by a substitute, not by the thing it asks for.
[docs/coding-style.md](docs/coding-style.md) §8 records why coverage-guided fuzzing is not in this
tree — it needs a nightly toolchain for sanitizer support — and what runs instead: a seeded mutation
harness, on stable, in CI, on every build. M6-03 also measured how much weaker that is, and the
answer was worse than expected: a deliberately reintroduced wrap bug survived half a million uniform
mutations because it needed an offset within sixteen of `u64::MAX`.

The harness now seeds those edges deliberately and finds that bug in the first few hundred cases.
A soak at M6-06 put **20 million mutated inputs through each of the three parsers** — `ustar`,
`elf`, and the ACPI table walker — with no panic, no hang, and no accepted image that violated an
invariant the mapper relies on. That is a real number and it is still not twenty-four hours of
coverage-guided fuzzing. **Phase
1 is therefore reported as "every task built" rather than "complete".** Closing this needs either a
nightly toolchain entry in `docs/nightly-features.md` with a justification, or an external fuzzing
harness run outside CI — a decision, not a task.

### 2026-08-04 (M6-06 — the first device Bhaskix finds rather than assumes)

- **A `virtio-blk` driver, and with it PCI.** Everything driven before this was the machine itself:
  timers, interrupt controllers, a UART that has been at port 0x3f8 since 1981. This device is
  *found* — enumerated on a bus, identified by what it says it is, configured through registers
  whose addresses come out of its own capability list, and driven through rings it reads by DMA.
- **`root=disk` mounts the filesystem off the device.** The same bytes by a completely different
  route: bootloader module in one case, PCI and a virtqueue in the other. Everything above the VFS
  — including the user-mode shell, which is a file — then comes from the disk without knowing it.
  M6's exit criterion asked to "load and run an ELF binary from disk"; this is the version where
  "from disk" is literal.
- **The disk is the ramdisk's own image, and that is what makes the test a test.** The kernel
  already has those bytes from the bootloader, so every sector read has a known answer. A driver
  that ignored the sector number was written on purpose: it reads sector zero four times, and fails
  on the second comparison rather than on a missing error code.
- **Modern virtio rather than legacy.** Legacy is a handful of I/O ports at a fixed layout and about
  a hundred lines less work; it is also a device model that new hardware does not implement and that
  QEMU disables by default on a PCI Express bus. Both device identities are accepted — a modern one
  says what it is in its device id, a transitional one in its subsystem id — because the two
  defaults are one QEMU flag apart.
- **Configuration mechanism 1, not ECAM.** Two I/O ports every PC has had since 1993, needing no
  ACPI table and no fallback for firmware that omits one. What it cannot reach is extended
  configuration space, which nothing needs yet; when something does, the address is built in one
  function and every caller keeps working.
- **A capability list is a linked list inside a device's configuration space**, and this one is
  walked with a bound. A device with a cycle in it — broken, or hostile — would otherwise be walked
  for ever during boot with interrupts disabled.
- **`make test-shell` now runs three configurations**: the user-mode shell, the ring 0 shell, and
  the user-mode shell with its filesystem read off the disk.

### 2026-08-04 (M6-05 — a shell that has to ask)

- **The machine boots to a program in ring 3 that holds two capabilities and nothing else.** It
  reaches the console through one and the filesystem through the other, sixteen bytes per message,
  and there is no third slot. `caps` asks the kernel about each: two are reachable and the third is
  refused before any service is involved — which is the difference between "the service said no"
  and "you have no authority", printed in different words because they are different facts.
- **The difference between the two shells is now visible rather than argued.** The kernel shell
  calls `vfs::open`. This one cannot: it has no filesystem, and withholding its capability turns
  both of its filesystem commands into refusals while `help` and `echo` carry on. That is the
  negative test, and it is the milestone in one sentence.
- **An ABI crate, compiled into the kernel and into unprivileged programs.** Six system call
  numbers, the message layout, the methods two services answer, and the line editor both shells
  use. Its `unsafe` budget is zero and should stay there: code here is trusted by the kernel *and*
  handed to untrusted programs, so an obligation in it would be owed on both sides of the boundary
  at once. The kernel's own `Kind` and `Status` are checked against it with a compile-time
  assertion, so two definitions of a syscall number fail the build rather than a message.
- **`Call` returned one register of a four-register message.** RFC 0008 says a message is four
  words; the syscall path returned `args[0]` and dropped the rest, which is why nothing had yet
  needed to answer with more than a number. Fixed, and the chunk protocol is the first thing to
  depend on it.
- **The first bug this milestone's own test found was a resource leak in a self-test.** `RESET`
  cleared a session's state but kept its slot, so the two callers the boot self-test used held both
  slots permanently and the shell was refused before it ever started. Typing at the machine found
  it in one run; nothing else would have. `RESET` now releases the session, and the honest note
  above records what still cannot be detected — a caller that dies.
- **Both shells are now typed at by CI.** `tests/qemu/shell-test.sh user` and `... kernel`; the
  second builds an image with `shell=kernel` on the command line and puts the default back.

### 2026-08-04 (M6-04 — the console reads, and there is a shell)

- **The machine can be typed at.** Until now nothing a device did could reach the kernel: the local
  APIC delivers the timer and messages between CPUs, and the path a device interrupt takes —
  pin, I/O APIC, vector, local APIC — had no middle. Finding the chip means walking the firmware's
  ACPI tables, so this milestone contains the project's third untrusted parser and its first that
  can be made to *hang* rather than crash: an entry-length field is a loop increment, and a table
  claiming zero is an infinite walk with interrupts disabled.
- **The RSDP was not where "the direct map covers physical memory" said it was.** On a BIOS machine
  it sits in the legacy area below one megabyte, which the memory map calls reserved and no
  bootloader maps. The first version dereferenced it and page-faulted during boot at an address
  that looked entirely plausible. The walk now asks the caller to map each range before it reads
  it, which also keeps the mapping out of `arch`, where no allocator exists.
- **The firmware's RSDT is not four-byte aligned on this machine.** An alignment check that looked
  defensive rejected real firmware and reported "no tables". Every field is read a byte at a time
  out of a slice, so alignment was never a correctness question here.
- **A latent one-CPU deadlock, found while making room for a second interrupt-context waker.**
  `on_tick` woke expired sleepers with a blocking runqueue lock. If the tick had landed on a thread
  holding that lock, the handler would have waited for a thread that could not run until the handler
  returned. Now `try_lock`, with undelivered wakes recorded and retried on the next tick — bounded
  by the idle backstop, one second, rather than never.
- **`match (flag, lock.try_lock())` holds the guard for the whole match.** The blocking arm then
  waited for a lock the scrutinee was holding: a self-deadlock on the first wake, which hung the
  wait-queue self-test. Written as an `if`, it is fine. This is the second time in this project that
  a temporary's lifetime in a `match` scrutinee has been the bug.
- **A new gate that writes to the kernel.** `tests/qemu/shell-test.sh` boots the machine, waits for
  the prompt, types five commands over the serial line and asserts on the replies — and only on the
  part of the log after the shell started, because the boot self-test runs the same commands with no
  console input at all. Removing the interrupt's wake-up leaves the boot gate green and fails this
  one, which is precisely the reason it exists.
- **The shell's commands are run by the boot self-test through the same function the prompt calls.**
  A shell whose commands can only be run by hand is a shell whose commands are tested by hand.
- **Everything the shell prints is filtered on the way out**, with two policies rather than one. A
  file's contents may contain newlines and tabs; a *name* may not. A name that could carry an escape
  sequence could move the cursor, clear the screen, or print a line that looks like it came from the
  kernel.

### 2026-08-04 (M6-02 and M6-03 — a filesystem, and a program loaded from it)

- **Ring 3 now runs a program the kernel did not contain.** `bin/probe` is built separately, put in
  the initial ramdisk, found by path, parsed as an ELF64 executable, and mapped at the addresses and
  with the permissions its own program headers name. Until now the same program was a byte array in
  the kernel image, copied into one page the kernel chose — which proved ring 3 worked and nothing
  about loading. This meets M6's exit criterion "load and run an ELF binary from disk".
- **The program proves the loading rather than the kernel asserting it.** Its first system call
  reports a value it can only have obtained by reading its own read-only segment at an absolute
  address, finding its writable segment zero-filled, storing there, and reading back. Four of the
  loader's obligations, in one number, none of which a `memcpy` of a flat blob could produce.
  **Negative-tested**: dropping a single segment from the mapper fails the gate.
- **`..` is refused rather than resolved.** It cannot escape a flat archive today. It becomes a
  directory traversal the moment a backend resolves paths against a tree, and by then the decision
  to accept it is years old and in a layer nobody rereads. **Negative-tested**: removing the check
  fails the boot gate.
- **A uniform-random fuzz harness could not find the bug it exists to find.** A wrapping bounds
  check, deliberately reintroduced in the ELF parser, survived half a million random mutations: an
  offset must land within sixteen of `u64::MAX` to wrap one, which is about one draw in 2^60. Half
  the field mutations now come from a list of adversarial constants, and the same bug is caught at
  seed 424. The lesson generalises past this parser — sampling uniformly tests the middle of the
  space and says nothing about the edges, which is where arithmetic breaks.
- **The loader refuses rather than clamps, everywhere.** A segment running off the end of the file,
  a `p_memsz` below `p_filesz`, an entry point outside every segment, a mapping in the kernel half,
  `PF_W | PF_X`, two segments sharing a page: each is a rejection with its own name. Clamping a
  segment that overruns its file still maps *something* at an address the program will jump to.
- **`ET_DYN` is refused, so there is no relocation processing in the kernel.** That is the whole of
  the dynamic-loader attack surface, declined by writing four bytes of comparison.
- **Bhaskix builds something that is not the kernel.** `user/probe` is outside the workspace, with
  its own code model, its own linker script, its own `unsafe` budget, and — checked by
  `tools/check-deps.py` — no dependencies at all. It reaches the kernel only through system calls.
- **Two gates added to the boot test** (28 assertions, from 26): the VFS and the ELF parser, and a
  ring 3 line that now names the file the program came from.

### 2026-08-04 (M6-01, the initial ramdisk — and a lost wakeup it exposed)

- **A lost wakeup in the IPC path, found because the initrd shifted the timing.** `call` and `recv`
  checked their mailbox and *then* marked themselves blocked. A message delivered in that window
  woke a thread that was not blocked yet, so the wake did nothing, and the thread slept with its
  answer already delivered. It measured as an IPC test that completed three rounds in eight seconds
  with both clients stuck mid-call.
  - The fix is the M4-09 rule in a place with no wait queue to enforce it: **mark blocked first,
    check second.** A message delivered before the mark is found by the check; one delivered after
    it sets the thread ready, and `block_self` returns without sleeping.
  - Two milestones of green runs did not find this. It needed a machine loaded enough to widen a
    two-instruction window, which is an argument for running the suite somewhere hostile rather than
    somewhere quiet.
- **`exit` halts instead of spinning on its runqueue lock**, the same fix `block_self` got in M5-05
  and the only other place a thread runs with nothing to do.

### 2026-08-04 (M6-01, the initial ramdisk)

- **The kernel has a filesystem image**, loaded by the bootloader as a module and handed over as a
  borrowed slice rather than an address and a length — so the kernel cannot read past it by
  arithmetic.
- **This is the first thing the kernel parses that an attacker controls end to end.** The archive is
  a file on the boot medium; anyone able to write that medium writes it. The reader is built to one
  rule: a malformed archive produces a *shorter* listing and never an out-of-bounds read.
- **A bad header ends the listing rather than being skipped.** "Skip the bad one and continue" is
  how a parser gets walked off the end of a buffer one malformed record at a time — and it is how a
  payload chosen to contain a plausible header gets read as one. Negative-tested: corrupting a
  single byte of the image drops the listing from six members to one.
- **The checksum is verified and explicitly not trusted.** An attacker computes it as easily as
  `tar` does. What it catches is a truncated or misaligned archive, where continuing would read a
  payload as a header — an integrity check, not a security one, and the source says so where someone
  might otherwise assume the opposite.
- **GNU tar's extensions are deliberately not implemented.** The build passes `--format=ustar` so
  they never appear, and a kernel that quietly understood a superset would be agreeing to parse
  whatever a future tool decided to emit.
- **The fuzz requirement is met by a seeded mutation harness rather than a coverage-guided fuzzer**,
  because the latter needs nightly and `nightly-features.md` is empty. One million mutated archives,
  no panic, seventeen seconds. The deviation and what it costs are recorded in
  `docs/coding-style.md` §8 rather than left to be discovered.
- **An API footgun found by hitting it.** `Archive` implemented `Iterator` *and* had inherent
  `find`/`count`; method resolution picked the trait's by-value versions and consumed the archive at
  the first call site that used them. Renamed to `lookup`/`members` rather than relying on rules
  most readers do not carry in their heads.

### 2026-08-04 (M5-06 and M5-07: quotas, and delegation from user mode)

- **Ring 3 derives a capability, uses it, and revokes it.** The probe asks the kernel to derive a
  second capability to the same endpoint with a badge *it* chooses, calls the service through it —
  which the service sees under the new badge — then revokes the parent, and the next call fails.
  Nothing about that was arranged by the kernel: it is a user program managing its own authority.
- **These are `Invoke` methods, not new system calls.** RFC 0008 fixes the set at six and says a
  seventh should feel like an architectural change. Granting authority is not one; it is an
  operation *on a capability*, which is what `Invoke` is for. Routing it that way also means a
  domain can only ever delegate something it was itself given, with no check to write.
- **Transitive revocation is now observable from user mode**, which is a different claim from the
  unit test that has covered it since M5-01. Negative-tested: making revocation stop at the root
  lets the derived copy survive, the fourth call reaches the service, and the gate goes red.
- **The quota is charged by owner, not by who revoked.** A capability records the domain that
  created it, and revocation tallies destroyed nodes per owner — because the subtree can span
  domains, which is the entire point of granting. Counting only the revoker's own would leak quota
  from every domain it had ever granted to.
- **A derive that cannot be installed destroys what it made.** Deriving into an occupied slot would
  otherwise leave a capability charged to the domain and reachable by nobody — a leak only a reboot
  clears. The same applies to the two-stage cross-domain grant, which unwinds if the recipient
  refuses it.
- **`GRANT` between domains is implemented and unexercised**, and recorded as such rather than
  counted as done.

### 2026-08-04 (M5-05b, IPC from ring 3 — the loop closes)

- **A user program calls a service and receives the answer.** Ring 3 → `SYSCALL` → domain lookup →
  CSpace → capability resolution → type check → badge → rendezvous → block → cross-CPU wake →
  resume → `SYSRET` → ring 3. Every layer built since M5-01 is on that path, and none of it was
  exercised end to end before.
- **The proof is that user mode sent the value back.** The service answers the first call with the
  request doubled; the second call carries that answer *in*. A reply the kernel delivered but ring 3
  never saw would otherwise be indistinguishable from one that arrived — a distinction the previous
  milestone's IPC test could not make either, because both ends were kernel threads.
- **This is also the first system call from ring 3 that blocks and comes back**, which is what
  per-thread kernel stacks were built for in M5-05 and had until now been justified rather than
  demonstrated.
- **The badge on the call is `0x12340000`**, from the capability the probe holds — a value the
  program cannot read, set, or replace. The service identifies its caller without asking it.
- **Negative-tested in the way that matters for a capability system.** Remove the capability from
  the probe's CSpace, or run the probe in no domain at all, and it still makes all twelve system
  calls — they simply reach nothing. That is the model working: authority is the argument, so a
  caller without one is not refused by a check, it has nothing to name.

### 2026-08-04 (M5-05, synchronous IPC — M5 feature-complete)

- **Rendezvous IPC, with no buffer in the nucleus.** A sender and a receiver meet, the message is
  copied directly, and both continue. What is queued is *threads*, which are already accounted for;
  buffering a message would force the nucleus to answer "whose memory is this", and every answer is
  a denial of service or the synchronous behaviour with extra steps.
- **Exercised through the whole system-call path**, not just the layer underneath: domain lookup,
  CSpace lookup, capability resolution, type check, badge extraction, then the rendezvous. The test
  clients call `syscall::dispatch` rather than `ipc::call`, so what is covered is what a user thread
  would actually take.
- **The badge is unforgeable by signature, not by checking.** `ipc::call` takes it as a separate
  parameter that only the dispatcher can produce, from the capability actually presented. Two
  clients hold differently-badged capabilities to the *same* endpoint and the service tells them
  apart without asking either. Negative-tested: sourcing the badge from the caller's frame instead
  makes both read as zero and the service cannot distinguish them.
- **Per-thread kernel stacks, installed on every context switch.** A blocking system call means a
  second thread can enter the kernel from user mode while the first is still there, so `RSP0` and
  the `SYSCALL` stack must belong to the thread rather than the CPU.
- **A tickless CPU woken by an IPI now re-arms its timer.** It was still armed for the one-second
  idle backstop, so a thread given to an idle CPU ran without a single interrupt — which is why the
  ring 3 probe was never preempted in user mode. Found because the ring 3 gate asserts on
  interrupts taken from ring 3, which is a line added in the previous milestone for exactly this
  class of miss.
- **An idle CPU now halts instead of spinning on its runqueue lock.** The old idle path re-took the
  lock every pass, and a remote CPU trying to deliver an IPC message competed with that loop for the
  cache line — the lock is not fair, so it could be starved indefinitely. It measured as a
  rendezvous that completed once and then stopped.
- **`try_lock` on a query produced a wrong answer for the third time.** `weight_of` reported "no
  such thread" for a thread on a busy CPU, failing the domain gate intermittently. `try_lock`
  belongs where failing is a valid outcome; a *query* is not such a place. Recorded in the honest
  notes because the pattern keeps recurring.
- **A comment corrected rather than a claim defended.** `sched::deliver` said writing the mailbox
  before waking prevents a lost wakeup. It does not — every waiter rechecks, so the wrong order
  costs a wasted switch and nothing else. Reversing it deliberately does not fail the gate, and the
  comment now says so.

### 2026-08-04 (M5-04, ring 3 — user mode runs)

- **A program runs in ring 3, calls into the kernel, and is interrupted there.** Ten system calls
  and six or seven timer interrupts from user mode on every boot. This also makes M5-03 real: the
  entry stub written last commit had never executed.
- **The evidence is *where* the kernel was entered from**, not that it was entered. A system call
  from user code arrives with a return address inside the user program's page (`rip 0x10000036`) and
  a stack pointer inside the user stack (`rsp 0x11001000`) — addresses this kernel never executes at
  and never uses as a stack. Counting system calls alone would look identical to calling the
  dispatcher directly.
- **The interrupt entry path now `swapgs`es when it interrupted user mode**, decided from the saved
  `CS`. Without it every `gs:`-relative access in the scheduler reads whatever user mode last put
  there.
- **`RSP0` is set, and the negative test shows why**: with it zero the probe completes nine of ten
  system calls and then takes an exception — the first interrupt from ring 3 pushes its frame at
  address zero.
- **A test that could not fail, made able to.** The first version of the probe was too short to be
  interrupted in ring 3 at all, so it exercised only the system-call path — and removing the
  interrupt-entry `swapgs` passed. The probe now spins in user mode between calls, and the gate
  requires a non-zero count of interrupts taken from ring 3. With that line present, removing the
  `swapgs` stops the kernel.
- **A syscall that never returns must hold no lock.** `Exit` was dispatched inside the capability
  arena's lock, and `sched::exit` does not return — so the lock was held for ever. M4-08's rule
  against preempting a lock holder then refused to switch that thread away, so it spun in `exit`
  and nothing ever released the arena. The next `cap::live()` hung. The rank machinery turned what
  would have been corruption into a visible stall, which is what it is for; the fix is to take no
  lock at all on a path that may not return.
- **`swapgs` bookkeeping corrected.** `IA32_KERNEL_GS_BASE` is initialised to *zero*, not to the
  kernel's per-CPU pointer: the invariant is that the kernel holds its area in `GS` and the user's
  value in `KERNEL_GS_BASE`, and the `swapgs` on the way out is what puts the kernel's value where
  the entry path will find it. Presetting it to the kernel base would have left user mode running
  with a `GS` base pointing into kernel per-CPU data.

### 2026-08-04 (M5-03, the `SYSCALL` fast path — partial)

- **The MSRs are programmed and read back rather than trusted.** `IA32_EFER.SCE`, `IA32_STAR`,
  `IA32_LSTAR` and `IA32_FMASK` are each written and then verified at boot, because every one of
  them is acted on by the CPU without further checking and three of them decide what privilege
  level the machine returns to. A wrong `IA32_STAR` does not fault; it returns to user mode with a
  stack descriptor that is really code.
- **The GDT layout `SYSRET` depends on is a compile-time assertion.** `SYSRET` takes no selector —
  it derives both from one MSR field, code at `+16` and stack at `+8` — so user data *must* sit
  immediately before user code. A reordering of `gdt.rs` that looks harmless is a privilege
  escalation, and it is now a build failure with a message saying which rule broke. Negative-tested
  by swapping the two selectors.
- **`IA32_FMASK` clears five flags, and each is a way for user mode to change how kernel code
  behaves.** `IF`, so an interrupt cannot land in the window between `swapgs` and the stack switch —
  the classic way this path is exploited. `AC`, or SMAP would be defeated for the whole call. Also
  `DF`, `TF` and `NT`. Negative-tested: dropping `IF` fails the gate.
- **The dispatcher is host-tested over every decision it makes**, including that all six syscall
  numbers decode and that everything outside them is refused as a *value* rather than used as an
  index.
- **There is no permission check, and that is the design.** A conventional handler resolves a name
  and then asks whether the caller is allowed it — two places to get wrong, one of which can race.
  Here the argument *is* the authority, so what remains is type checking: a thread capability is
  refused where an endpoint is expected, before anything is dereferenced.
- **"Never had one" and "had one, revoked" stay distinct status codes.** Collapsing them would make
  a revocation bug indistinguishable from a caller bug, which is the confusion a security review
  can least afford.
- **Built on RFC 0008's recommendation, not its acceptance.** ~~The decision is still a draft
  awaiting a verdict; if A2 or A3 is answered differently, this is the code that changes.~~
  **Resolved: RFC 0008 was accepted on 2026-08-04 and this code did not change.** The risk was real
  when it was written and it did not materialise, which is worth recording either way — a note that
  is only kept when it turns out badly is a note that flatters the project.

### 2026-08-04 (M5-02, domains and the resource envelope)

- **The envelope refuses.** `docs/security.md` T10 says it is enforced "at allocation and scheduling
  time, not by best effort", and the wording is doing work: a limit checked after the fact, or
  treated as a hint to a reclaim policy, does not answer T10 — it describes it. `charge_frames`
  returns an error and applies nothing, which is the only behaviour that means anything to the
  *other* domains.
- **CPU share is divided among a domain's threads, not given to each.** A per-thread weight makes a
  domain with ten threads take ten times the CPU of a domain with one, which turns the envelope into
  a suggestion and makes spawning threads a privilege-escalation strategy that needs no bug.
  `docs/scheduler.md` §3's claim — "honoured regardless of how many threads it spawns" — is now
  arithmetic rather than aspiration, and §10's one-thread-versus-many comparison is a gate.
- **Destroying a domain revokes its whole derived subtree**, before `destroy` returns, using M5-01's
  root capability. Everything a domain was ever granted descends from that one capability, which is
  what makes teardown total rather than a sweep of somebody's tables.
- **The gate asserts the mechanism and reports the measurement.** An earlier version asserted the
  measured CPU ratio and failed about one run in three; the same run showed correct weights and a
  4.6:1 measured ratio, which settled it — the ratio is emulator noise and the weights are the
  property. Weights are gated, the ratio is a printed note. Negative-tested: multiplying the share
  instead of dividing prints `weights [1024, 1024, 1024, 1024], 1024 vs 3072 total`.
- **A bug found by making the test deterministic.** Re-weighting a domain's threads originally
  skipped any runqueue whose lock was contended — and the threads being re-weighted are exactly the
  ones running on that queue, so contention was likely rather than rare. It measured as a domain
  with three threads taking twice the CPU of one instead of the same. The path blocks now; it holds
  no other lock, and every scheduler path reachable from an interrupt uses `try_lock`.

### 2026-08-04 (M5-01, capabilities — and RFC 0008 answering three open decisions)

- **RFC 0008 drafted**, resolving **A2**, **A3** and **A4** together, because they are one decision
  seen from three angles: the nucleus provides mechanism that cannot be *named* without authority,
  and refuses to hold state on anyone's behalf.
  - **A2 — capability invocation, not a numbered table.** Six syscall kinds, ever. A numbered table
    makes an operation available because of what the caller *is*, which is ambient authority and
    discards the project's central security claim on the first syscall.
  - **A3 — synchronous rendezvous is primitive.** Buffering forces the nucleus to answer "whose
    memory is this message in", and every answer is either a denial of service or the synchronous
    behaviour with a buffer's complexity added. Async is shared memory plus a notification
    capability, one layer up — the shape `io_uring` converged on, needing the nucleus to provide
    exactly one thing: a way to wake someone.
  - **A4 — the native ABI is A2.** There is no separate native ABI to design. Consequence worth
    stating: **no native `libc`**; the roadmap's Phase 2 libc belongs to the Linux personality.
- **Capabilities implemented, and all four rules of `docs/security.md` §2 are individually
  negative-tested** — each one broken on purpose, each breaking its own test and no other.
  - Derivation monotonicity is tested over **every one of 64×64 rights pairs**, not sampled. §2 asks
    for exhaustive and a sampled version would pass while missing the combination that matters.
  - Revocation is transitive *and* inert outside the subtree, which is the half a naive
    implementation gets wrong, and both directions are gated.
  - A stale reference never resolves to a reused entry — the use-after-free that hands out authority
    instead of crashing, which is the worst possible version of it.
- **The derivation tree is global rather than per-domain**, because revocation must cross domains:
  the whole point of granting is that the capability ends up somewhere else. A domain's CSpace holds
  references into that tree, so revoking a node invalidates every slot referring to it without
  traversing a single domain — the slots were never the authority.
- **Built before the syscall interface on purpose.** Capabilities sit below the ABI decision, so
  M5-01 could proceed while RFC 0008 waits for a verdict.

### 2026-08-04 (M4-12, per-CPU frame reserve — M4 complete)

- **The page-fault path no longer touches the physical allocator.** Each CPU keeps a small reserve of
  frames it has already taken, and faults spend those. Refilling happens from the timer interrupt, a
  context that can afford to fail and retry.
- **The reserve needs no lock, and that is the design rather than an optimisation.** A CPU's reserve
  is touched only by that CPU, so the only concurrency is an interrupt arriving mid-update, and
  interrupts are masked for the few instructions involved. Every alternative ends in a lock the
  fault handler must not wait for — which was the old behaviour: try the lock, and when it was held
  report the fault unserviceable. Honest, and a kernel that failed at exactly the moments it was
  busiest for no reason the workload could see or avoid.
- **The gate holds the real lock and then faults inside it.** A closure runs with the allocator's
  lock held by this CPU and writes to a page that has never been mapped; the handler must complete
  without going near that lock. A mock lock would have proved the handler avoids a lock nobody was
  holding. Negative-tested: emptying the reserve makes it report `no frame in this cpu's reserve`.
- **Every frame-leak check had to learn about reserves.** A frame in a reserve has left the
  allocator's free count without being lost, so `available_frames` counts both. Without that, the
  project's most trusted gate would have reported a refill as a leak — and been believed.
- **`unsafe` budget for `bhaskix-kernel` raised 460 → 460** (unchanged; the reserve costs 12 lines
  and fitted inside M4-10's raise).
- **M4 is complete.** Threads, SMP, per-CPU runqueues, work stealing, lock ranking, sleeping and
  wait queues, scheduling classes, tickless timers, TLB shootdown and now the fault-path reserve.
  What M4 does *not* have is recorded in the honest-notes section above and is longer than the list
  of what it does: no priority inheritance, no domain-level fairness, no timer wheel, no reclaimed
  stacks, and a real-time wakeup latency that is measured and over budget.

### 2026-08-04 (M4-10, tickless idle and one-shot timers)

- **The APIC timer is one-shot.** Re-armed after every interrupt for exactly as long as the next
  thing that needs attention: the running thread's remaining slice, or the soonest pending timer,
  whichever comes first. Ticklessness is not a feature layered on top of that — it is what a
  one-shot timer does when asked for nothing.
- **Measured, not asserted: 0 timer interrupts over 400 ms with the machine idle**, against 320–483
  with every CPU busy. The gate is the *ratio* between two equal windows, because the absolute
  number depends on the tick rate, the CPU count and the host's load, and the property does not.
- **A tickless CPU can only be woken by an interrupt**, which made the reschedule IPI (M4-09b) a
  prerequisite rather than a nicety. Cross-CPU wakes are now prompt: the ring self-test went from 84
  laps to 736, and the recheck window in `block_self` started actually being hit — 0 races before,
  2–3 now, which is the first direct evidence that race is real.
- **Then a second fix, from the same cause.** *Spawning* a thread on an idle CPU also has to poke
  it; missing that presented as three worker threads that never ran. The rule is now explicit and
  stated in the source: every operation that makes a thread runnable on another processor must say
  so. This is the class of bug ticklessness introduces, and it is silent.
- **An idle CPU is still armed once a second.** Strictly unnecessary, and kept because "strictly" is
  doing a lot of work in that sentence — it assumes every present *and future* path remembers the
  IPI. The backstop converts a silently lost thread into a thread that ran late.
- **Exited threads now release their queue slot.** Reaped lazily when a slot is wanted, never the
  thread the CPU is currently on — it is still executing inside `exit` on its own stack. Without
  this the fifth test phase failed with `QueueFull`. Stacks are still not reclaimed.
- **An interrupt storm, from a deadline that was momentarily stale.** The timer is armed inside the
  handler, *before* the scheduler renews the quantum, so at every slice boundary the stored deadline
  was in the past and the arming asked for the remaining zero nanoseconds. The measured tick rate
  went from 400 a second to over thirty thousand — a machine spending all its time in its own timer
  handler. The deadline query now renews a stale deadline itself.
- **A fairness bias traced to rounding, and then to the emulator.** A 3:1 weight ratio measured
  3.7:1 on hardware. A host simulation of the same pick-and-charge loop gave exactly 3.0, which
  narrowed it to the environment: the arming divide rounded *down*, so every slice was delivered
  slightly short — and a heavy thread's virtual time advances in smaller increments, so a constant
  shortfall costs it proportionally more, and it needed a fourth slice where three should have done.
  Rounding up helped; the residue is emulator jitter, with repeated runs spreading 1.9–3.7 on
  unchanged code.
- **The fairness gate was therefore widened to 1.5–6.0x and the reason recorded.** Tightening it
  would make the gate a coin toss. The exact ratio is proved where it can be — a unit test that runs
  the real loop with time as an exact input and requires 3.0x. `docs/scheduler.md` §10's ±2% remains
  **unmet** and needs real hardware; the widened band is not quoted as the target.
- **`unsafe` budget for `bhaskix-kernel` raised 430 → 460**, reason recorded in `kernel/Cargo.toml`.

### 2026-08-04 (RFC 0007 drafted, live patching)

- **RFC 0007 drafted**: live patching the nucleus, scoped deliberately small. Draft, awaiting a
  decision.
- **It narrows the request rather than expanding it.** Bhaskix puts drivers, filesystems, network
  and storage in relocatable service domains, and a domain can be *restarted* — an ordinary,
  testable, reversible operation, unlike modifying code that is currently executing. What is left is
  the nucleus, which is small by design. The best live patch is a small nucleus, and that is an
  architectural advantage a monolithic kernel cannot claim.
- **The competitor is stated fairly and is the default.** A/B atomic reboot is already on the Phase 3
  roadmap and answers most of the same need. The decisive difference is assurance: a live patch runs
  against a machine state no test reproduced, while a rebooted image runs exactly what was tested.
  For a system aiming at certification that has to be weighed, not assumed away.
- **The requirement is real and comes from RFC 0004**: OT availability of 99.99%+ with maintenance
  windows measured in hours per year. A security gateway that must be taken down to patch itself is
  one that does not get patched.
- **The most important consequence is for attestation, not for patching.** `docs/security.md` §8
  measures the boot image. A live patch changes the running kernel afterwards, so an attestation
  reporting only the boot image would report a known-good state for a machine running modified code
  — actively misleading rather than merely incomplete. Measured state must become image *plus* the
  ordered list of applied patches.
- **Rust's inlining makes this harder than it is in C.** With LTO there may be no call to redirect
  and no named copy of the buggy code. Patchability is therefore a property of the *build*, a patch
  is not portable between builds, and the tooling must answer "is this patchable in this image" from
  the image rather than the source.
- **Shadow data, patching service domains, patching the boot path, unsigned patches even in
  development, and automatic application are all refused** — not deferred.
- **P0 is the part that matters today**: a stable build identifier and an attestation format that can
  express applied patches. Both are nearly free now and painful to add to a shipped, certified
  system, which is the reason to write this RFC long before building the feature.

### 2026-08-04 (M4-07, scheduling classes — and four bugs it exposed)

- **Real-time and fair classes, in strict priority.** Fixed priorities 0–99 with `FIFO` and `RR`,
  weighted proportional share with virtual deadlines beneath them, and an idle class below that. The
  whole policy is one pure function over the runqueue, so all thirteen class rules are unit-tested on
  the host and each fails when its own rule is removed.
- **The deadline earns its place.** A thread asking for a *shorter* slice gets an earlier deadline and
  so runs sooner and more often for the same total share — how a latency-sensitive thread declares
  itself rather than being guessed at from its sleep pattern. Measured weight ratio at 3:1 is 2.7–3.1x.
- **Admission control refuses rather than degrades**, and real-time threads are excluded from work
  stealing: the budget is per-CPU, so migrating one invalidates it at both ends.
- **Accounting moved to the TSC**, because a 100 Hz tick cannot distinguish 200 µs from 9 ms and
  proportional fairness measured in ticks is not proportional fairness.

Four defects surfaced, three of them pre-existing and serious:

1. **The interrupt-enable flag was not part of a thread's context.** A thread yielding voluntarily,
   with interrupts on, could be resumed from inside an interrupt handler with them off — and then
   run on with the timer masked. That does not delay one thread, it stops the clock for the whole
   machine, and every other thread waits on a tick that never comes.
2. **Voluntary preemption was not atomic against the timer.** A tick landing between choosing the
   next thread and performing the switch re-entered the scheduler on the same thread; both calls
   then switched from their own stale view. It surfaced as a #GP on `iretq` from a corrupted
   interrupt frame — as far from the cause as a symptom gets. Both paths now mask for the duration
   of the decision and the switch.
3. **Nothing stopped a thread being preempted while holding a spinlock** — recorded as an open gap
   at M4-08 and now closed using that milestone's own rank mask, which already tracks what the CPU
   holds. On one processor this was a deadlock: the holder cannot release until it runs, and the
   spinner holds nothing, so the scheduler saw nothing wrong and kept choosing the spinner.
4. **`make iso` did not depend on `CMDLINE`.** Every fault-injection case after the first booted the
   *previous* case's image, so different subsets failed on different runs and it read as flakiness.
   This had been quietly weakening the fault gate, and it also explains the unreproducible hang
   recorded at M4-06.

- **Accounting had to move before the decision, not after.** `preempt` returns early when the running
  thread is still the right choice, so charging afterwards meant a thread that won one comparison was
  never charged again: its deadline froze at the winning value and it owned the CPU for ever.
- **An unbounded virtual-time lead starves.** A thread that once ran alone is far ahead in virtual
  time, and a group of threads that each run for microseconds before blocking accrue so slowly that
  it never runs again. Bounded at eight slices — deliberately generous, so it never fires under
  ordinary contention.
- **A test assertion was removed for measuring timing rather than policy.** Load-aware placement races
  with stealing by design, so asserting *which* CPU it chose failed about one run in three. It is
  reported now; the policy belongs in a unit test, not a live race.
- **The QEMU harness now polls instead of always waiting out the timeout.** The kernel halts rather
  than exiting, so every run cost the full timeout — which made the timeout impossible to tune, since
  long enough for a loaded machine also meant minutes of dead waiting. `make test` went from over ten
  minutes to 51 seconds, and the timeout went back to being an upper bound.
- **Toolchain moved to Rust 1.97.1** from 1.90.0, at the user's prompting. Two new lints found real
  sloppiness: casting a function item straight to an integer, and a hand-rolled checked division.

### 2026-08-03 (RFC 0006 drafted, Kosh storage)

- **RFC 0006 drafted**: `Kosh` (कोष, treasury) names the storage system and scopes the distributed
  tier — elastic from a single node, RF=1…n per volume, block/file/object/key-value over one
  substrate, heterogeneous geo-replication. Draft, awaiting a decision.
- **It commits to the row RFC 0003 marked "not committed"**, and does not withdraw that RFC's
  estimate: Ceph-scale distribution is a decade-scale programme. The document is therefore
  structured so the first two stages are independently useful and form a clean stopping point — a
  Merkle-checksummed, copy-on-write, capability-scoped store on one machine, which is what RFC 0003
  argued an evaluator actually needs.
- **The claims that cannot be made truthfully are stated first, not last.** RF=1 is not durable and
  must be reported as `Unprotected`; RF=2 on two nodes cannot survive a partition without a witness
  or a declared primary; cross-site replication is asynchronous because of the speed of light, so it
  has a non-zero RPO that must be measured and published rather than implied away; and "universal"
  describes the interface, not performance on all three workloads at once.
- **`n = 1` is not a special case** is called out as the hardest constraint. A separate single-node
  mode is two products with a migration between them, and the migration is the part users discover
  is risky.
- **Cluster membership ships before replication, deliberately.** Building both together means the
  first cluster test cannot distinguish a placement bug from a replication bug.
- **Automatic cross-site failover and synchronous geo-replication are refused outright**, not
  deferred, along with Ceph/S3 wire compatibility — which would mean inheriting the semantics RFC
  0003 exists to avoid.
- **Data locality is a scheduler decision, not a storage one.** Reads are served from the nearest
  healthy replica; writes cannot be local, because a synchronous write at RF=n is only durable when
  every replica has it. The interesting lever is moving the *compute* — Bhaskix schedules VMs and
  containers as domains and Kosh knows which nodes hold which extents, so "start this VM where its
  disk already is" is a decision the system can make. It is expressed as a weight the scheduler may
  trade off, never a constraint: locality and load balancing conflict directly, and a hard
  constraint turns a busy node into a queue.
- **Disaster recovery is separated from high availability, with the numbers named.** HA is
  within-site, synchronous, RPO zero, automatic. DR is cross-site, asynchronous, RPO non-zero and
  measured, RTO minutes, operator-initiated. Automatic cross-site failover is refused. Rehearsal is
  a first-class operation, because a failover procedure that has never been run is the thing that
  fails in the incident; and failback resynchronises by Merkle difference, because a full re-copy
  after every failover is how sites quietly stop failing back.
- **Replication is not backup**, and the RFC says so where a reader cannot miss it: replication
  copies destructive writes faithfully, so RF=3 across three sites is three copies of the ransomware.
  Snapshots are the answer, and an immutable snapshot means the capability that shortens retention
  is separate from the one that writes — expressible under the capability model in a way a
  permission bit is not.
- **The deepest open question is a capability question, not a storage one**: how authority survives
  a hop, so that a node holding a replica can serve it without holding authority over everything.
  It blocks the replication stage.

### 2026-08-03 (M4-09, sleeping and wait queues)

- **Threads can sleep.** A `Blocked` state, a `WaitQueue` with a bounded intrusive-free waiter list,
  and a cross-CPU `wake`. Until now the only way to wait was to spin, which cost a processor per
  waiter and — more to the point — made "no lost wakeups" not merely unproven but *inexpressible*,
  because nothing ever slept.
- **Waking stays inside M4-06's ownership rule.** It is the one place a CPU touches a thread in
  another CPU's queue, and it changes a `state` field under that queue's lock and never reads or
  writes a context. The woken thread is still scheduled by its own CPU, on its own stack.
- **The safety property was made structural because the test could not see it.** Enqueueing a
  waiter and marking it blocked must be one step: a waker only wakes threads already `Blocked`, so
  an entry belonging to a still-`Ready` thread is worse than no entry — the waker removes it, wakes
  nothing, and the thread sleeps forever. That bug was written on purpose and **the ring test passed
  anyway**, 52 laps, because the window is a handful of instructions. The two steps are now fused
  into one function so they cannot drift apart. A property a test cannot see should not be left to
  a convention.
- **A documented mechanism turned out to be documented wrongly.** The recheck in `block_self` was
  described as what closes the lost-wakeup race. It is not: by then the waker has already written
  `Ready`, and a `Ready` thread is picked up by round-robin regardless. What it actually provides is
  the loop's *exit* — deleting it hangs the kernel, because a thread woken in the gap with nothing
  else runnable on its CPU spins in the block path forever. Establishing that took deleting it and
  watching the kernel stop.
- **The gate requires three things at once**, because each hides a different way of passing without
  working: laps (a lost wakeup stops the ring dead rather than slowing it), non-zero sleeps (a ring
  that spun instead of sleeping proves nothing), and non-zero wakeups (threads woken rather than
  merely preempted onto). Negative-tested by disabling `wake`: laps `[1,1,1,0]`, zero wakeups.
- **A lost wakeup caused by migration, found by the thread table.** The waiter list originally
  recorded *which CPU* held each sleeper, so a wake could go straight to the right runqueue. That is
  wrong in a way that only shows up once work stealing exists: a thread is immune to migration only
  while it is `Blocked`, and a thread sleeping in a loop is `Ready` in between. Stolen in that gap,
  its recorded CPU goes stale and the next wake searches a queue that no longer holds it. The ring
  stalled at `[1,1,1,1]` with one station `Blocked` and marked `(migrated)` — which is the only
  reason it was diagnosable, and an argument for printing provenance in diagnostics. Waiters are now
  keyed by thread identifier, which is globally unique and cannot go stale; `wake` searches. The
  earlier claim that recording the CPU was migration-safe was true only *within* a single wait, and
  is corrected in the source.
- **A threshold tuned to the fastest configuration failed on the slowest.** The ring gate first
  required five laps, which BIOS cleared easily and UEFI did not — the framebuffer console is slow
  enough to turn the ring several times slower. It now asserts *shape* rather than speed: every
  station went round more than once, and no station is more than one lap ahead of another, which is
  what a ring guarantees when healthy and what a lost wakeup breaks.
- **A self-inflicted lock-order violation, caught by the previous milestone's gate.** `block_self`
  first took the runqueue lock with `lock()` rather than `try_lock()`, so the rank joined the held
  set and was then captured as the outgoing thread's — which carried a lock it did not hold to
  wherever it next ran. Twelve reports per boot, from the checker added the day before.

### 2026-08-03 (M4-08, lock ranking)

- **Every lock now declares its rank at construction.** `SpinLock::new` takes a `Rank`, so a lock
  cannot be added without saying where it sits — which is the rule `docs/coding-style.md` §7 asked
  for, expressed as a type signature rather than as a convention.
- **The declared order was recovered from the code, not invented, and two entries are not where
  intuition puts them.** `heap::HEAP` ranks *outside* `tlb::SENDER`, because unmapping frees frames
  inside `heap::with` and must shoot down before the frame is reused. And `sched::QUEUES` ranks
  *inside* the heap: a thread can be preempted while holding the heap, and the switch path then
  blocks on a runqueue. `sched::spawn_on` had already arrived at the same constraint independently
  by allocating outside the runqueue lock.
- **`try_lock` is exempt, and that is the load-bearing part.** A deadlock is a cycle in which every
  edge is a blocking wait, so a non-blocking acquisition can never be one. It matters because
  interrupt handlers acquire locks where the hardware chooses: a timer can land while any lock is
  held, so every lock taken in interrupt context is out of rank with respect to something.
- **The boot line reports what was checked, not just what was found.** Zero violations is exactly
  what a checker that never ran also reports, so the kernel states the number of acquisitions it
  checked (~7,400) and then proves the detector fires by provoking a deliberate inversion on a pair
  of locks created for that purpose.
- **Held ranks belong to the thread, not the CPU.** A thread preempted while holding the heap
  carries its held set with it; without that, the next thread to run on that CPU would inherit an
  ordering constraint it had no part in.
- **Deviation from the documented rule, recorded rather than quiet.** §7 said debug builds should
  panic; this reports and continues, as `lockdep` does. Halting on the first report discards the
  rest of the boot's coverage, and a rank violation is a latent risk rather than present
  corruption. `docs/coding-style.md` §7 and `docs/architecture.md` §6 now say so.
- **A bug I introduced and then caught the slow way.** The violation predicate had the mask
  direction backwards, so the checker was inert: it reported nothing on any input. The unit tests
  written alongside it encode the correct direction and would have failed immediately — I had not
  run them before booting. Running the host tests before the emulator would have found it in
  seconds instead of a boot cycle.
- **One unexplained hang, not carried forward as fixed.** A single `-smp 4` boot stopped after the
  TLB line while the checker was inert. Six consecutive runs afterwards were clean, and the
  evidence points to a partially built ISO rather than the kernel. It is recorded here because
  "could not reproduce" is the honest status, not "fixed".

### 2026-08-03 (RFC 0005 drafted, Linux ABI compatibility)

- **RFC 0005 drafted**: the Linux `x86_64` system-call ABI as a **domain
  personality** — a translation layer running in a service domain, implementing Linux calls on top
  of capabilities its domain already holds. Draft, awaiting a decision.
- **The narrow first target is the proposal, not a caveat.** Statically linked Go binaries with
  `CGO_ENABLED=0` remove the dynamic linker, `libc`, NSS and locale from the problem in one move,
  and Go issues raw syscalls, so the surface is the kernel ABI alone. "Enough Linux ABI for static
  Go" is a far smaller target than "enough for Docker", and choosing the smaller one deliberately
  is what makes it finishable.
- **It has to reconcile with RFC 0003, which argues POSIX is the wrong primitive.** The resolution
  is that the Linux ABI is a *personality*, exactly as POSIX is one row of RFC 0003's Layer 2 table
  — "paid only by callers who ask". Three rules make that real: no Linux concept enters the
  nucleus, the personality is never a source of authority, and native software does not link it.
  The RFC states that if those are ever relaxed for convenience it should be reverted rather than
  patched.
- **Docker and Kubernetes are answered by separating two questions.** Running OCI *images* needs
  no Docker daemon and is already on the Phase 3 roadmap; running `dockerd` would need namespaces,
  cgroups, overlayfs and seccomp-bpf, and would replace the domain model with Linux's. Position:
  OCI images yes, Docker daemon never. Kubernetes is named only so nothing forecloses it.
- **Recorded as decision C1**, and it reframes open decision **A4** (userspace ABI) rather than
  answering it: the own-ABI-versus-POSIX choice is a false one, but the native shape still needs
  deciding before M5.

### 2026-08-03 (M4-06b, work stealing and migration)

- **A CPU that would otherwise idle takes work from a busier one.** `docs/scheduler.md` §5 calls
  this the idle pull and expects most balancing to happen here, because it is free: the CPU had
  nothing to do. Creation also places a thread on the least-loaded CPU, which is cheaper than
  moving it afterwards.
- **Stealing moves ownership, which is what keeps the previous milestone's soundness argument.**
  A thread leaves the victim's queue and enters the thief's, under one lock at a time, and is
  afterwards owned by the thief exactly as if it had been created there. At no point do two CPUs
  hold pointers to the same context.
- **Three rules make that true, and every one of them is invisible when broken.** Only `Ready`
  threads move; never from a CPU partway through a switch; never the thread a CPU booted on. The
  middle one is the subtle one: a thread is marked `Ready` *before* the switch that saves its
  registers, and the runqueue lock is released in between — it has to be, since the incoming thread
  takes it — so `Ready` alone admits a thread whose context is not yet written.
- **The policy is unit-tested, not boot-tested, and that was a deliberate correction.** The first
  attempt at a negative test removed the pinned-thread rule and the boot test still passed: the
  hazard is a race that a single boot cannot be relied on to provoke. Extracting the decision into
  one pure function made each rule fail a specific test when removed, which is the difference
  between a rule that is enforced and a rule that is merely written down.
- **`STEAL_IMBALANCE = 2`, not 1.** At one, a thief with a single thread takes from a CPU with two,
  leaving two and one — and the victim, now lighter, takes it straight back. The thread migrates
  forever instead of running.
- **A bug in the test, found by a consistency check in the test.** The steal counter and the
  per-thread migration counters are written together under one lock and cannot legitimately
  disagree; asserting that caught the load-placement thread writing into migrant 0's record,
  because both were passed the same index. Without that check the phase would have reported success
  on two runs out of three.
- **Latent stack misalignment in the thread trampoline, fixed in passing.** It called the entry
  point with RSP 0 modulo 16, where the ABI promises 8. Nothing had noticed because the target
  disables SSE, and nothing would have until the first aligned vector access.

### 2026-08-03 (M4-06, per-CPU runqueues)

- **One runqueue per CPU, each with its own lock.** The throughput argument for this is real and is
  not why it landed now. The single-queue scheduler was *unsound* on more than one processor: it
  took raw pointers into a shared thread table and switched to them after releasing the lock, which
  is correct only if exactly one CPU is ever inside it. Making the queues per-CPU removes the
  sharing rather than protecting it — a CPU touches only its own threads' contexts, so there is
  nothing to race against.
- **Secondaries are now full scheduling CPUs.** Each registers its own queue with its current
  execution as the first thread, starts its own APIC timer, and idles interruptibly. Threads created
  on a secondary are preempted by that secondary's own timer, out of its own queue, with no lock
  shared with any other processor.
- **The boot test asserts the property, not the mechanism.** A global runqueue would still preempt;
  what distinguishes this is *where* threads run. The test spawns one worker per online CPU and
  requires worker *i* to observe itself on CPU *i*. Verified by breaking it: forcing every spawn
  onto CPU 0 produces three failures, and the gate goes red.
- **A page fault at `CR2 = 0` traced to segment-load semantics** — see M4 bug 2. The general lesson
  is that establishing per-CPU state is not one step: the identity is needed *before* the
  descriptor tables are built, and the `GS` base can only be set *after*, because building them
  destroys it.
- **`unsafe` budget for `bhaskix-kernel` raised 400 → 430**, with the reason recorded in
  `kernel/Cargo.toml` as the gate requires: an ordering-critical bring-up sequence where one
  `unsafe` block per step is what makes each ordering constraint documentable at the point it
  applies, plus the switch path's raw context pointers.

### 2026-08-03 (M4-05b and M4-11, per-CPU tables and shootdown)

- **Every CPU builds its own GDT, TSS and IST stacks.** Sharing them was not merely unwise, it does
  not work: `ltr` marks a TSS descriptor *busy*, so a second CPU claiming the same one faults. And a
  shared IST means two processors double-faulting at once land on the same stack and destroy each
  other's report — at exactly the moment the machine is least able to explain itself.
- **Secondaries now idle with interrupts enabled**, which is what makes them reachable at all.
  Halting with interrupts disabled — what they did before they had their own TSS — makes a CPU
  unable to answer anything, and any shootdown wait for it would spin until it gave up.
- **TLB shootdown works.** An IPI to all-but-self, with the sender waiting for every acknowledgement
  before returning, because the caller's next act is usually to free the frame. Negative-tested:
  disabling the receiving handler turns 8 completions into 8 timeouts.
- **Shootdown is skipped for address spaces no CPU has loaded**, which is a correctness observation
  before it is an optimisation: a translation can only be cached by a CPU that has run in that
  space. It is also what stops tearing down a thousand address spaces from costing a thousand
  rounds of IPIs.
- **A self-inflicted test bug worth recording.** `"timed out"` was added as a failure marker, and it
  matches the *success* message `"none timed out"` — so every passing run failed. Substring markers
  need to be checked against the strings they will actually see.

### 2026-08-03 (M4-05, CPUs online)

- **Secondary CPUs come online.** 1, 2, 4 and 8 all work; each claims a per-CPU area through an
  atomic and installs it as its `GS` base, so `gs:[0]` reaches different state on every processor
  with no lock and no lookup. The boot tests now run with four CPUs and assert N-of-N came online —
  asserting "more than one" would read as success on a machine that happens to be smaller.
- **The bootloader starts them.** Doing it by hand means a real-mode trampoline and an INIT/SIPI
  sequence with its own timing requirements; worth owning eventually, not before the kernel can use
  a second CPU for anything. The mechanism stays in `boot/shim` — the kernel receives a callback and
  never learns how a CPU is started.
- **They park, deliberately, and the tracker says why.** Shared GDT/TSS means shared IST stacks, the
  TLB shootdown gap is now a live bug rather than a theoretical one, and the scheduler assumes one
  CPU. Bringing CPUs up while being explicit that they idle is more honest than scheduling on them
  and finding all three in production.

### 2026-08-03 (M4, threads preempt)

- **Threads exist and the timer preempts them.** Real kernel threads, each on its own guarded stack,
  switched by `bhaskix_context_switch`. Three workers that never yield all made progress, which only
  the timer can have caused — negative-tested by removing the `preempt` call, which zeroes every
  counter.
- **One bug worth the whole exercise.** New threads started with interrupts disabled: a thread that
  has run before resumes through `iretq` and gets `RFLAGS` back, but a brand-new one is entered by a
  `ret` from inside an interrupt gate that cleared `IF`. The first thread scheduled therefore ran
  with interrupts off forever and the machine stopped — no exception, no triple fault, nothing to
  read. Found in QEMU's interrupt trace, which simply ended.
- **This is round-robin, not the fair scheduler**, and the tracker says so rather than letting the
  milestone name imply otherwise.

### 2026-08-03 (M3-13, KASLR — M3 complete)

- **KASLR works.** The kernel is now built as a position-independent executable, so the bootloader
  slides the image and fixes up its 403 relative relocations. Verified across boots: the base moved
  every time, and the boot test asserts a non-zero slide — losing KASLR otherwise looks identical to
  having it.
- **Two things had to change for it.** The exception table now stores self-relative offsets rather
  than absolute addresses, because an absolute address in a read-only section needs a dynamic
  relocation the linker refuses to emit there; Linux's table is built the same way for the same
  reason. And the link script gained an explicit `PT_DYNAMIC` segment — declaring PHDRS by hand
  means nothing is created implicitly, and the loader rejected the image with "ET_DYN, but
  PT_DYNAMIC segment missing" until it was added. A precise error message from Limine turned what
  could have been a long debugging session into a five-minute fix.
- **A fourth silently-failed patch.** The KASLR reporting edit matched nothing because rustfmt had
  rewrapped the surrounding `println!` — the same failure mode as three previous occasions. Caught
  by grepping for the new string rather than trusting the build.

### 2026-08-03 (M3-12, user access)

- **`copy_from_user` and `copy_to_user` land, with an exception table.** A fault at the copy
  instruction resumes at a recovery path and returns an error, so a hostile or simply wrong user
  pointer is ordinary input rather than a kernel defect. Negative-tested: disabling the table
  produces an unhandled page fault at exactly the address the test passes in.
- **SMEP and SMAP are enabled.** SMAP means a kernel access to a user page faults *even when the
  page is mapped*, so the copy routines bracket their access with `stac`/`clac` inside the assembly
  — the window is a few instructions wide and cannot be left open by an early return.
- **A range check, not just a fault check.** A user pointer aimed at kernel memory would otherwise
  succeed whenever that memory happens to be mapped, which is the confused-deputy bug the check
  exists to prevent; the fault handler cannot tell a kernel address the caller meant from one an
  attacker supplied.
- **Fixed a fault loop I had introduced.** The handler returned `Handled` for an already-present
  page, which retries the faulting instruction forever. SMAP makes that reachable, since a kernel
  access to a *mapped* user page faults and the mapping being there is what made it look
  serviceable.
- **The demand-paging test now goes through `uaccess`** rather than raw volatile writes, which is
  both required by SMAP and a better test — it proves demand paging works underneath a user copy.

### 2026-08-03 (M3 exit criterion met)

- **Demand paging and copy-on-write work**, which makes the region map authoritative in fact rather
  than only in structure: a fault consults the map, and demand paging and COW are the same mechanism
  reading different fields. Negative-tested by breaking the demand-paging arm, which produces an
  unhandled page fault instead of a quiet pass.
- **The kernel ran in an address space it built**, loading `CR3` for the first time. That closes the
  gap recorded when address spaces landed — until now the higher-half copy that keeps the kernel
  mapped had never been exercised.
- **The fault path uses `try_lock` throughout.** A fault can interrupt code already holding the
  allocator lock, and spinning there would hang the machine with no output; it reports an
  unserviceable fault instead. A limitation made visible rather than solved.
- **CI is green**, all nine jobs including every firmware/CPU combination. The OVMF pairing fix was
  correct.

### 2026-08-03 (published, CI live)

- **Pushed to `github.com/bhaskix/bhaskix`.** 9 commits, 93 files. Verified before publishing that
  no tooling files were tracked, that no vendor string appears anywhere in history rather than
  merely in the working tree, and that every commit is authored and DCO-signed by
  `tarunsoft1@gmail.com`.
- **`SECURITY.md` added**, because `docs/security.md` §9 promised a reporting channel that went
  public with no way to act on it. Written to be honest about the stage — it opens by stating the
  project has never been audited and must not be deployed — and includes a section on what is *not*
  a vulnerability yet, since this project documents its unfinished work openly and a report of a
  protection already tracked as unimplemented costs the reporter their time for nothing.
- **CI ran for the first time and found two real defects.** Details in §3.

### 2026-08-03 (M3, guarded stacks)

- **The M2 gap is closed.** The kernel switches off the bootloader's unguarded stack onto a 64 KiB
  stack with an unmapped guard page below it, and the `df` fault test now overflows it with real
  recursion rather than an artificial trigger. The report shows `rsp` at exactly the stack bottom
  and `cr2` 8 bytes into the guard page — the page fault cannot be delivered on the exhausted
  stack, so it escalates to a double fault, which IST1 catches and reports.
- **The guard is verified, not assumed**: boot asserts the guard page is genuinely unmapped and the
  stack genuinely mapped. If the address had happened to be mapped already, the "guard" would be an
  ordinary writable page and the mechanism would be a no-op that still printed success.
- **A patch silently failed to apply again** — the stack-switch block never landed because rustfmt
  had rewrapped the surrounding `println!`. The result booted and page-faulted with `cr2 = cr3 +
  0xa00`, because the handoff copy the switch was supposed to populate stayed zeroed. Second
  occurrence of this failure mode; the lesson stands that a clean build proves nothing about
  whether the code runs.
- **A test failed on its own wording**: the boot check matched `M1 complete` and broke when the
  banner said `M3`. Now milestone-agnostic.

### 2026-08-03 (M3, address spaces)

- **The M3 frame-leak gate passes**: 1000 address spaces created, mapped, translated through, and
  destroyed with the free-frame count returning to exactly its baseline. Negative-tested by removing
  the page-table teardown, which leaks 9 frames per cycle and fails the gate.
- **`Protection` makes W+X unrepresentable** — there is no variant for it, so the invariant is
  checkable by reading the enum rather than by auditing call sites. `EFER.NXE` is enabled before the
  first mapping and asserted at boot.
- **`RangeMap` is the source of truth**, with the page table as its cache, per `docs/memory.md` §3.
  14 host tests, including one checking the binary search against a linear scan across every address
  in a small space, and one asserting that whatever `find_free` suggests, `insert` accepts.
- **A deadlock avoided by design, and documented**: the region map is a `Vec`, so touching it
  allocates through the global allocator, which takes the heap lock the physical allocator lives
  behind. Region-map work therefore happens strictly outside that lock.

### 2026-08-03 (M3, kernel heap)

- **`alloc` works in the kernel.** Slab allocator over the buddy allocator, wired to
  `#[global_allocator]`; `Box` and `Vec` verified on real hardware paths in QEMU under both BIOS and
  UEFI, with a boot assertion that no frames leak.
- **Slab metadata lives in the frame database, not in the slab page**, as `docs/memory.md` §4
  requires: metadata sharing a page with the objects it describes can be corrupted by an overflow of
  those objects, and a corrupted free-list head hands the same memory out twice.
- **12 more host tests**, over a real page-aligned buffer so the pointer arithmetic is exercised
  rather than modelled — including a 20,000-operation mixed-traffic test that writes through every
  allocation to catch overlap, and asserts every slab page returns to the buddy allocator.
- **The `unsafe` budget now excludes test code**, which was distorting the number it exists to
  produce: the auditable surface of the kernel *as deployed*. `docs/coding-style.md` §3 updated, and
  the checker re-negative-tested to confirm it still catches unjustified blocks in shipped code.

### 2026-08-03 (M3, physical memory)

- **Buddy allocator and frame database landed.** Orders 0–10, DMA32 and Normal zones, free lists
  threaded through the frame database so coalescing is O(1) with no auxiliary allocation. 34 host
  tests in `mm`, including a 20,000-operation randomised property test asserting zero frame leakage
  and full coalescing.
- **Boot-time frame-leak self test** runs on every boot: 252 MiB managed on a 256 MiB machine, and
  the allocator returns to exactly its starting free count.
- **Two real bugs caught by the invariant checker and by reading the boot log** rather than by the
  compiler — the handover corruption and the split frame database. Both recorded in §3.
- **The `unsafe` checker was itself wrong** and is now negative-tested.

### 2026-08-03 (M2-08)

- **Interrupts are live.** Legacy PIC remapped and masked, Local APIC enabled, timer calibrated
  against PIT channel 2 and running at 100 Hz. Boot tests now assert *observed ticks* and `hlt`
  wakeup rather than merely that the enable code ran, on both BIOS and UEFI.
- **Both APIC paths implemented** — x2APIC via MSRs (no mapping needed, and required for >255 CPUs
  in M4) and xAPIC via MMIO. QEMU 4.2 forced the xAPIC path; see §3.
- **Bump allocator (M2-11) and a minimal page mapper (M2-13) landed early**, pulled forward because
  mapping the xAPIC register page was the only way to get a timer under this emulator. 9 host tests.
- **CPU feature reporting added** — the boot log now states which of the guarantees in
  `security.md` §4 the machine can actually provide, rather than assuming.
- **RFC 0004 drafted**: operational technology as the first deployment target.

### 2026-08-03 (later)

- **M2 exit criterion met.** GDT with IST stacks, IDT across all 256 vectors, uniform `TrapFrame`,
  and a decoding exception reporter. `tests/qemu/fault-test.sh` injects six fault types (#DE, #UD,
  #BP, #GP, #PF, #DF) and asserts each is reported with correct decoded detail and that QEMU logged
  no triple fault.
- **Three subtle bugs found and fixed** — `lateout` register aliasing, segment-limit encoding
  polluting the descriptor base, and Rust's overflow checks pre-empting the hardware #DE. Details
  in §3.
- **The panic handler is no longer unverified** — the first `de` test run reached it through Rust's
  divide-by-zero check and it printed correctly. That closes the M1-07 gap recorded yesterday.
- **RFC 0003 (storage architecture) drafted** — proposes a capability-scoped, Merkle-checksummed
  object store as the primitive, with POSIX as one personality among several, and a phased plan
  whose Phase 3 is the certifiable set rather than a distributed filesystem.

### 2026-08-03

- **M1 substantially complete: the kernel boots.** BIOS and UEFI, on Limine 8.7.0 base revision 3.
  Serial and framebuffer console both working; handoff validated; `make test` green end to end in
  ~80 s (fmt, clippy ×2, 17 host tests, 3 project gates, 2 boot tests).
- **Gates caught real defects on first run**, which is the point of having them: two `unsafe`
  blocks in `limine.rs` with no `// SAFETY:` justification, a missing SPDX header, and a
  self-referential flaw in the vendor-string checker.
- **Fixed a stale-image bug in the Makefile** found by negative-testing the boot test: `make iso`
  could rebuild the kernel without regenerating the ISO, so the boot test could pass against an old
  image. The ISO now depends on the phony build target and is always regenerated.
- **Boot test negative-tested** — deliberately broke the banner and confirmed the harness fails,
  then restored and confirmed it passes. A test that cannot fail is worse than no test.
- **`arch` unsafe budget set from measurement** (88 lines used, budget 95) rather than guessed.
- **Toolchain is stable Rust only** — no `#![feature]` anywhere; `docs/nightly-features.md` records
  the policy and the anticipated pressure points.

### 2026-08-02

- **Renamed VyomOS → Bhaskix** (N1, RFC 0002). 36 files, zero residual occurrences. Crate prefix is
  now `bhaskix-`/`bhaskix_`. Done at Phase 0 deliberately: no users, no contributors, nothing
  published — the same change after Phase 1 would have touched every fork and article.
  **Outstanding:** GitHub org handle and domain are not yet claimed, and no trademark search has
  been done. Both must happen before the first public push.
- **Toolchain verified working** — Rust 1.90.0 with `x86_64-unknown-none`, QEMU 4.2.1, xorriso,
  OVMF, and Limine v8.7.0 all installed and building.
- **A1 resolved: Apache-2.0.** `LICENSE` and `NOTICE` added; workspace manifest updated. External
  contributions can now be accepted. (RFC 0001)
- **M1 started.** Task breakdown M1-01 … M1-18 defined with exit criteria.
- **TRACKER.md created** as the single source of truth for project status.
- **Phase 0 design documents complete** — vision, architecture, memory, scheduler, security,
  driver-model, ai-native, coding-style, roadmap, repo-layout, RFC template.
- **Governance established** — benevolent-dictator model with written dissolution conditions at five
  maintainers. DCO, no CLA.
- **Repository initialised**; project structure created.
- **Founding decisions recorded** — D1 Rust, D2 Limine-behind-Handoff, D3 nucleus with relocatable
  services, D4 domains unify containers and VMs.
