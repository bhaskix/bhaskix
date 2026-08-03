# Bhaskix — Project Tracker

**This file is the single source of truth for project status.** If any other document, issue, or
conversation disagrees with this file about *what is done* or *what is next*, this file wins.

| | |
|---|---|
| **Last updated** | 2026-08-03 |
| **Phase** | Phase 1 — Foundation |
| **Active milestone** | **M4 — Threads and scheduling** |
| **Overall progress** | M1 17/18 (hardware blocked) · M2 MET · M3 COMPLETE · M4 threads preempt · CI green |

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
| **A2** | Syscall ABI shape | ⬜ Open | Capability-invocation only vs a numbered syscall table. | *Blocks M5* |
| **A3** | IPC style | ⬜ Open | Synchronous rendezvous vs async buffered channels. Which is primitive? | *Blocks M5* |
| **A4** | Userspace ABI | ⬜ Open | Own ABI vs POSIX-shaped. Determines what software can ever be ported. | *Blocks M5* |
| **A5** | 5-level paging (LA57) | ⬜ Open | Support from day one, or assume 4-level and parameterise? | *Blocks M3* |

> **Correction to an earlier note:** A2–A5 were previously recorded in `roadmap.md` as blocking M1
> exit. They do not — M1 is boot and output, which none of them touch. The real gates are as shown
> above. A1 blocked *accepting external contributions*, and is now resolved.

---

## 3. Active milestone — M4: Threads and scheduling

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
| M4-05 | SMP bring-up (AP trampoline, per-CPU areas) | ⬜ `TODO` | **Blocks the exit criterion** |
| M4-06 | Per-CPU runqueues, work stealing | ⬜ `TODO` | Needs M4-05 |
| M4-07 | Fair class (virtual deadline), RT class | ⬜ `TODO` | Currently plain round-robin |
| M4-08 | Lock ranking, active in debug builds | ⬜ `TODO` | `docs/coding-style.md` §7 requires it |
| M4-09 | Sleeping, wait queues, blocking | ⬜ `TODO` | A thread is runnable or finished; nothing waits |
| M4-10 | Tickless idle, timer wheel | ⬜ `TODO` | Timer is a fixed 100 Hz tick |
| M4-11 | TLB shootdown | ⬜ `TODO` | **Correctness bug the moment a second CPU exists** — `unmap_page` invalidates only the local TLB |
| M4-12 | Per-CPU frame reserve for the fault path | ⬜ `TODO` | Would let a fault be serviced while the allocator lock is held |

### Bugs found and fixed during M4

1. **New threads started with interrupts disabled, and the machine simply stopped.** A thread that
   has run before resumes through `iretq`, which restores `RFLAGS` and with it the interrupt flag.
   A brand-new thread has no such frame — it is entered by a `ret` from inside the timer's interrupt
   gate, which cleared `IF` on entry. So the first thread scheduled ran with interrupts off forever,
   the timer never fired again, and there was no crash to look at: no exception, no triple fault,
   just a halt. Diagnosed from QEMU's interrupt trace ending at a timer vector with nothing after.
   Fixed with an `sti` in the thread trampoline.
2. **My own trampoline design was internally inconsistent** — it expected the entry point in `rax`,
   which the context switch does not restore. Caught while writing it; entry point and argument now
   travel in `r12` and `rbx`, which are callee-saved and therefore actually preserved.

### Honest notes on what is *not* proven

- **This is round-robin, not the scheduler `docs/scheduler.md` specifies.** No priorities, no
  fairness weighting, no virtual deadlines, no RT class, no admission control. The fairness figure
  printed at boot is reported rather than asserted, because a tight bound on round-robin would be
  measuring timer jitter rather than any property worth defending.
- **One CPU.** Everything about per-CPU runqueues, load balancing and work stealing is untouched,
  and the scheduler takes raw pointers into a static thread table on the assumption that only one
  CPU is inside it.
- **Threads cannot block.** There is no sleep, no wait queue and no wakeup path, so "no lost
  wakeups" — half the exit criterion — is not merely unproven but not yet expressible.
- **Thread capacity is fixed at 16** and stacks are never reclaimed. `exit` marks a thread finished
  but its stack stays mapped, so thread creation is effectively one-way.
- **No lock ranking**, which `docs/coding-style.md` §7 requires and which becomes load-bearing the
  moment there are enough locks to order.

### Blockers

| Task | Blocked on | Owner |
|---|---|---|
| M1-17 | Physical UEFI machine with serial. QEMU cannot substitute. | Tarun Kumar Kushwaha |
| Repo metadata | GitHub description and topics are unset, and `main` has no branch protection — `GOVERNANCE.md` §2 requires review for non-trivial changes and nothing enforces it. Deploy keys have no API scope, so these need the web UI. | Tarun Kumar Kushwaha |
| CI log access | Reading Actions logs needs authentication; unauthenticated API gives 60 requests/hour and only pass/fail. A fine-grained token with `Actions: read` would remove both limits. | Tarun Kumar Kushwaha |

## 4. Upcoming milestones

Scope and exit criteria are in [docs/roadmap.md](docs/roadmap.md). Not started; listed so the
dependency order is visible.

| Milestone | Scope | Status | Gated on |
|---|---|---|---|
| M2 | GDT, TSS, IDT, exceptions, APIC, bump allocator | `TODO` | M1 |
| M3 | Buddy PMM, paging, slab heap, COW, demand paging, KASLR | `TODO` | M2, **A5** |
| M4 | Threads, context switch, runqueues, SMP, timers | `TODO` | M3 |
| M5 | Capabilities, domains, syscalls, user mode, IPC | `TODO` | M4, **A2, A3, A4** |
| M6 | VFS, ELF loader, shell, virtio-blk | `TODO` | M5 |

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
| Both service placements build | Phase 2 | architecture.md §2 |
| AI-degradation test (kill `bhaskixd-ai`, suite still passes) | Phase 4 | ai-native.md §4 |

---

## 7. Changelog

Newest first. One entry per meaningful change of project state.

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
