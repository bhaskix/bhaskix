# Bhaskix — Project Tracker

**This file is the single source of truth for project status.** If any other document, issue, or
conversation disagrees with this file about *what is done* or *what is next*, this file wins.

| | |
|---|---|
| **Last updated** | 2026-08-03 |
| **Phase** | Phase 1 — Foundation |
| **Active milestone** | **M3 — Memory management** |
| **Overall progress** | M1 17/18 (hardware blocked) · M2 MET, gap closed · M3 6/8 remaining items done |

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

## 3. Active milestone — M3: Memory management

**Physical memory is done. Virtual memory has not been started.** M3's exit criterion is not yet
met and will not be until address spaces exist.

**Milestone exit criterion** ([docs/roadmap.md](docs/roadmap.md) M3): host property tests for buddy
and slab pass; the frame-leak test passes in QEMU; `alloc` types usable throughout the kernel.

| ID | Task | Status | Verified by |
|---|---|---|---|
| M3-01 | Frame database, one entry per frame | ✅ `DONE` | 65,503 entries / 1.28 MiB on a 256 MiB machine |
| M3-02 | Buddy allocator, orders 0–10 | ✅ `DONE` | 26 host tests incl. a 20,000-operation randomised leak/coalescing property test |
| M3-03 | DMA32 zone, never satisfied from above 4 GiB | ✅ `DONE` | Dedicated tests for the boundary and for no block straddling it |
| M3-04 | Bump → buddy handover | ✅ `DONE` | Consumed ranges tracked and excluded *before* frames reach a free list |
| M3-05 | Invariant checker | ✅ `DONE` | Walks every free list; caught the handover bug on first run |
| M3-06 | Boot-time frame-leak self test | ✅ `DONE` | Runs on every boot, not only under test |
| M3-07 | Slab allocator as `GlobalAlloc` | ✅ `DONE` | 12 host tests over real page-aligned memory; `Box` and `Vec` verified working in QEMU on BIOS and UEFI |
| M3-08 | `AddressSpace`, `RangeMap`, page tables | ✅ `DONE` | 14 host tests for the region map; map/unmap/translate/create/destroy in QEMU |
| M3-09 | W^X and NX enforcement | ✅ `DONE` | `Protection` has no write+execute variant; `EFER.NXE` enabled and asserted at boot |
| M3-10 | Demand paging and copy-on-write | ⬜ `TODO` | Mappings are eager for now; needs the page-fault handler to consult the region map |
| M3-11 | Kernel stack guard pages | ✅ `DONE` | **Closes the M2 gap.** The kernel runs on a 64 KiB guarded stack; the `df` fault test now uses real recursion and faults at `cr2 = guard + 0xff8` |
| M3-12 | `copy_from_user` / `copy_to_user` with fixups | ⬜ `TODO` | Needed before user mode in M5 |
| M3-13 | KASLR | ⬜ `TODO` | |
| M3-14 | Address-space frame-leak gate (1000 create/destroy) | ✅ `DONE` | Passing, and **negative-tested**: removing page-table teardown leaks 9 frames per cycle and the gate catches it |

### Bugs found and fixed during M3

0. **The kernel's `#[global_allocator]` broke the host test suite.** The attribute applies to the
   whole binary, so under `cargo test` it replaced the *host* harness's allocator with one backed by
   physical memory that does not exist — the harness failed to allocate 4 bytes before running a
   single test. Now registered only under `cfg(not(test))`.
1. **The bump→buddy handover corrupted the free lists.** Marking bump-allocated frames reserved
   *after* adding their regions to the free lists left frames that were simultaneously on a free
   list and reserved. The invariant checker caught it on its first run, which is the entire reason
   it was written before the code that needed it. Fixed by having the bump allocator record what it
   consumed and subtracting those ranges before any frame reaches a free list.
2. **The frame database could not be allocated.** It must be one unbroken array, but the first
   usable region on a PC is a ~300 KiB fragment below the legacy hole. Frame-by-frame allocation
   silently produced a database split across the gap. Fixed with `allocate_contiguous`, which skips
   regions that cannot hold the whole run.
3. **A patch silently did not apply.** An earlier edit to wire in `memory::init` did not match, so
   the module compiled as dead code and the boot output simply lacked a section. Caught only by
   reading the boot log rather than trusting the build. Worth remembering: a clean build proves
   nothing about whether the code runs.
4. **The `unsafe` checker rejected a justification that was present.** rustfmt wrapped a long `let`
   across two lines, putting code between the SAFETY comment and its block. The scanner now
   continues past statement continuations and stops at a real statement boundary — and was
   negative-tested to confirm it still catches genuinely unjustified blocks.

### Honest notes on what is *not* proven

- **No address space has ever been *switched to*.** Everything is created, mapped, translated
  through, and destroyed while the kernel runs in the bootloader's address space. Loading `CR3`
  with one of these is M5's job, and until that happens the higher-half copy is untested in the only
  way that matters.
- **W^X is enforced but not *attacked*.** The `Protection` type cannot express write+execute and NX
  is on, but nothing yet tries to execute a writable page and confirms it faults. That test belongs
  with the fault-injection suite and is not written.
- **Mappings are eager, not demand-paged.** The region map is authoritative in structure, but the
  page-fault handler does not consult it yet, so the design's central claim — that demand paging,
  COW, and file-backed mappings are one mechanism — is unproven.

- **The 4 GiB zone boundary has never been exercised on real memory.** QEMU was given 256 MiB, so
  every frame is in the DMA32 zone and the `Normal` path is covered only by host tests.
- **No per-CPU magazines.** `docs/memory.md` §2 specifies them for the order-0 hot path. There is
  no SMP and no lock yet, so they would be untestable machinery guarding against contention that
  cannot occur. Deferred to M4 with the second CPU.
- **The frame database is sized by the highest usable address**, so a machine with a large gap
  between RAM banks wastes database entries on the hole. Acceptable now; revisit if a target
  platform has a sparse map.
- **Nothing has been tested above 4 GiB of RAM**, so the `u32` PFN limit (16 TiB) and the zone
  fallback path are untried in practice.
- **`Frame` grew from 20 to 36 bytes** when `SlabInfo` was added, taking the frame database from
  1.28 MiB to 2.25 MiB on a 256 MiB machine — about 0.9% of RAM. Linux overlays these fields in a
  union instead. Worth doing, not yet done.
- **No red zones, poisoning, or quarantine** in the slab allocator. `docs/memory.md` §4 specifies
  them for debug builds. They are debugging aids rather than correctness, and were left until the
  `alloc` machinery worked well enough to test them against.
- **The slab has never been exercised under memory pressure** — every test had ample free frames, so
  the out-of-memory paths inside `grow` are covered only by the deliberate-exhaustion unit test.

### Blockers

| Task | Blocked on | Owner |
|---|---|---|
| M1-17 | Physical UEFI machine with serial. QEMU cannot substitute. | Tarun Kumar Kushwaha |
| — | GitHub org, crates.io name, and domain for `bhaskix` are **unregistered and unverified**. Account creation requires a human. | Tarun Kumar Kushwaha |

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
