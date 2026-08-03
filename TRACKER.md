# Bhaskix — Project Tracker

**This file is the single source of truth for project status.** If any other document, issue, or
conversation disagrees with this file about *what is done* or *what is next*, this file wins.

| | |
|---|---|
| **Last updated** | 2026-08-03 |
| **Phase** | Phase 1 — Foundation |
| **Active milestone** | **M2 — CPU state and interrupts** |
| **Overall progress** | M1 17/18 (hardware blocked) · M2 exit criterion MET, scope partially complete |

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
| **A2** | Syscall ABI shape | ⬜ Open | Capability-invocation only vs a numbered syscall table. | *Blocks M5* |
| **A3** | IPC style | ⬜ Open | Synchronous rendezvous vs async buffered channels. Which is primitive? | *Blocks M5* |
| **A4** | Userspace ABI | ⬜ Open | Own ABI vs POSIX-shaped. Determines what software can ever be ported. | *Blocks M5* |
| **A5** | 5-level paging (LA57) | ⬜ Open | Support from day one, or assume 4-level and parameterise? | *Blocks M3* |

> **Correction to an earlier note:** A2–A5 were previously recorded in `roadmap.md` as blocking M1
> exit. They do not — M1 is boot and output, which none of them touch. The real gates are as shown
> above. A1 blocked *accepting external contributions*, and is now resolved.

---

## 3. Active milestone — M2: CPU state and interrupts

**The exit criterion is MET.** Every exception produces a clear diagnostic instead of a triple
fault, proven by `tests/qemu/fault-test.sh` across six injected fault types. **The milestone scope
is not fully complete** — the APIC work remains. Both facts are recorded rather than one of them.

**Milestone exit criterion** ([docs/roadmap.md](docs/roadmap.md) M2): *"every exception vector
produces a clear diagnostic instead of a triple fault. A test that deliberately triggers a page
fault, a GP fault, and a double fault reports all three correctly and does not reboot the machine."*

| ID | Task | Status | Verified by |
|---|---|---|---|
| M2-01 | GDT with kernel/user code and data descriptors | ✅ `DONE` | Boots; SYSRET-compatible ordering for M5 |
| M2-02 | TSS with IST stacks for double fault and NMI | ✅ `DONE` | The `df` fault test reports instead of resetting |
| M2-03 | IDT, all 256 vectors populated | ✅ `DONE` | Stub table disassembled and verified: 16-byte spacing, correct error-code handling per vector |
| M2-04 | Interrupt stubs normalising into a uniform `TrapFrame` | ✅ `DONE` | Register dumps show correct values in fault reports |
| M2-05 | Exception reporter with decoded error codes | ✅ `DONE` | 6 fault types, each asserting on decoded detail not just presence |
| M2-06 | Fault injection via kernel command line | ✅ `DONE` | `bhaskix.fault=` |
| M2-07 | Fault-injection test harness | ✅ `DONE` | `tests/qemu/fault-test.sh`; asserts QEMU logged no triple fault |
| M2-08 | Local APIC, IO-APIC, APIC timer | ⬜ `TODO` | **Not started.** Not required by the exit criterion, but is M2 scope. |
| M2-09 | Legacy PIC masking | ⬜ `TODO` | Needed before interrupts are enabled |
| M2-10 | `arch::Arch` trait boundary | ⬜ `TODO` | Deferred; see note |
| M2-11 | Boot-time bump allocator | ⬜ `TODO` | Moves naturally into M3 with the rest of `mm` |
| M2-12 | Per-CPU data area | ⬜ `TODO` | Deferred to M4 with SMP bring-up, where it is actually needed |

### Bugs found and fixed during M2

Recorded because each was subtle, cost real time, and would recur:

1. **`lateout` register aliasing in `load_gdt`.** The register allocator reused an input register
   for the `lateout` temporary, so the `lea` clobbered the data selector and the segment loads used
   garbage. `lateout` explicitly permits this; `out` does not. Fixed by using `out`.
2. **Segment limit encoding.** The 20-bit limit is split across bits 0-15 and 48-51. Writing the
   whole `0xfffff` into the low bits puts `0xf` into the *base address*. In 64-bit mode the base is
   nominally ignored, so this booted fine right up until the far return in `load_gdt`, where the
   target landed at base+offset — mid-instruction — and the CPU executed garbage. Diagnosed from
   QEMU's `-d int` showing `CS base=0xf` and `pc = rip + 0xf`.
3. **Divide-by-zero never reached the CPU.** `overflow-checks = true` makes Rust emit an explicit
   zero test and panic first. Correct behaviour, kept; the test now issues `div` in assembly.

### Honest notes on what is *not* proven

- **Kernel stack overflow is still untestable.** The realistic cause of a double fault is stack
  overflow, and it cannot be tested yet: the kernel stack is Limine's and **has no guard page**, so
  an overflow scribbles over mapped memory (in practice the page tables) until the machine dies in
  a way no handler can report. Guard pages need virtual memory management. The `df` test uses a
  deterministic unmapped-stack trigger instead, which exercises IST1 and the handler but *not* the
  overflow path. **Tracked as an M3 task.**
- **No interrupts have ever been delivered.** Only exceptions. Interrupts stay disabled until the
  APIC work (M2-08) lands, so the `iretq` return path in `isr_common` is exercised only by `#BP`.
- **`arch::Arch` (M2-10) is deliberately deferred.** Defining a portability boundary with exactly
  one implementation and no second architecture in sight produces a trait shaped like x86. It is
  more honest to define it when AArch64 work begins than to guess now — this reverses the position
  in `architecture.md` §7 and that document should be updated to say so.

### Blockers

| Task | Blocked on | Owner |
|---|---|---|
| M1-17 | Physical UEFI machine with serial. QEMU cannot substitute. | Tarun Kumar Kushwaha |

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
