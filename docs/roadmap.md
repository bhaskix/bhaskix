# Bhaskix — Roadmap

*Status: living document. Milestones are ordered by dependency, not dated.*

We do not publish dates. An unfunded volunteer kernel project that publishes dates publishes
disappointments. What we publish instead is **ordering** and **exit criteria**: a milestone is done
when its criteria pass in CI, and not before.

Every milestone has an exit criterion that a stranger can verify by running a command.

---

## Phase 0 — Design (current)

**Goal:** every load-bearing decision written down before it is made accidentally in code.

| Item | Status |
|---|---|
| [vision.md](vision.md) | ✅ adopted |
| [architecture.md](architecture.md) | ✅ draft — needs review |
| [memory.md](memory.md) | ✅ draft — needs review |
| [scheduler.md](scheduler.md) | ✅ draft — needs review |
| [security.md](security.md) | ✅ draft — needs review |
| [driver-model.md](driver-model.md) | ✅ draft — needs review |
| [ai-native.md](ai-native.md) | ✅ draft — needs review |
| [coding-style.md](coding-style.md) | ✅ adopted for Phase 1 |
| Open decisions A1–A5 resolved by RFC | ⬜ **blocks M1 exit** |
| Dev environment reproducible (`tools/setup-dev.sh`) | ⬜ |
| CI: build, fmt, clippy, host tests, QEMU boot | ⬜ |

**Exit criterion:** a new contributor clones the repo, runs `tools/setup-dev.sh && make run`, and
gets a QEMU window. Documents reviewed by at least two people who did not write them.

**Note on A1 (license):** this must be settled before the first external contribution is accepted.
Relicensing a project with contributors is painful; relicensing one without them is free.

---

## Phase 1 — Foundation

### M1 — Boot and output

*Vision milestone 1: "Boot with UEFI, print Hello from Bhaskix".*

- Limine boot on UEFI (and BIOS, which comes free)
- `boot/` shim → `bhaskix_boot::Handoff`
- Serial (16550) driver — the debugging lifeline, written first
- Framebuffer text output from the handoff
- `panic_handler` that prints to serial and halts
- Build system: `make`, `make run`, `make test`; bootable ISO via `xorriso`

**Exit:** `make run` prints `Hello from Bhaskix` to both serial and framebuffer, on UEFI and BIOS,
on QEMU, and boots on at least one piece of real hardware.

### M2 — CPU state and interrupts

*Vision milestone 2.*

- GDT, TSS, per-CPU data, IST stacks for double-fault and NMI
- IDT, all 32 CPU exceptions with useful register dumps
- Local APIC, IO-APIC, APIC timer
- `arch::Arch` trait boundary defined ([architecture.md](architecture.md) §7)
- Boot-time bump allocator ([memory.md](memory.md) §1)

**Exit:** every exception vector produces a clear diagnostic instead of a triple fault. A test that
deliberately triggers a page fault, a GP fault, and a double fault reports all three correctly and
does not reboot the machine.

### M3 — Memory management

*Vision milestone 3.*

- Frame database; buddy PMM with per-CPU magazines; `DMA32` zone
- `AddressSpace`, `RangeMap`, 4-level page tables, W^X, NX
- Slab allocator as `GlobalAlloc` — `Box`/`Vec`/`BTreeMap` work
- Demand paging, COW, guard pages, `copy_{from,to}_user` with fixups
- KASLR

**Exit:** host property tests for buddy and slab pass; the **frame-leak test** (create/destroy 1000
address spaces, assert free-frame count returns exactly to baseline) passes in QEMU; `alloc` types
usable throughout the kernel.

### M4 — Threads and scheduling

*Vision milestone 4.*

- `Thread`, `Context`, kernel stacks with guard pages, `bhaskix_context_switch` in asm
- Per-CPU runqueues, Fair class (virtual deadline), Idle class
- SMP bring-up (AP trampoline, per-CPU init)
- Lock ranking infrastructure, active in debug builds
- Timers: APIC deadline mode, timer wheel, tickless idle

**Exit:** N threads across M CPUs, 10⁷ ping-pong iterations, no lost wakeups, no stranded threads,
lock-rank assertions clean. Fairness test: two equal-weight workloads get 50/50 ± 2%.

### M5 — Domains, capabilities, syscalls, user mode

*Vision milestone 5.*

- Capability objects, CSpace, derive/revoke with transitive revocation
- `Domain` with `ResourceEnvelope`
- `SYSCALL`/`SYSRET` entry, syscall dispatch, SMAP bracketing — the interface is
  specified by [RFC 0008](rfc/0008-syscall-and-ipc-shape.md) (accepted): six syscall
  kinds, all authority arriving as a capability argument
- Ring 3 execution
- Synchronous IPC (call/reply) with badges

**Exit:** a user-mode program runs, invokes capabilities, is denied what it does not hold, and is
killed cleanly when it faults. A test asserts transitive revocation completes before the syscall
returns. Two domains cannot see each other's memory — verified, not assumed.

### M6 — Filesystem, ELF, shell

*Vision milestone 6.*

- VFS layer; a simple on-disk filesystem (initially read-only, `initrd`-backed)
- ELF64 loader — with a fuzz target, per [coding-style.md](coding-style.md) §8
- Kernel shell, then a user-mode shell over the syscall interface
- virtio-blk driver

**Exit:** boot to a shell, `ls` a real filesystem, load and run an ELF binary from disk. The ELF
loader survives 24 hours of fuzzing without a crash.

**Phase 1 complete.** Bhaskix is a real, if minimal, operating system.

---

## Phase 2 — Core Operating System

Order within the phase is flexible; dependencies are noted.

- **Process management** — fork/exec-equivalent (capability-shaped, not POSIX-shaped), process trees,
  reaping, signals-equivalent
- **Full VFS** — mount points, a writable filesystem with a journal, page cache
- **Shared memory and notifications** — [RFC 0009](rfc/0009-shared-memory.md) (accepted) and
  [RFC 0010](rfc/0010-notifications.md): a `Memory` object a capability names, and a doorbell to go
  with it. Between them they complete RFC 0008's answer to A3, and they precede everything below:
  a service framework whose bulk paths move sixteen bytes per round trip is a framework nobody will
  measure twice
- **Service framework** — [RFC 0013](rfc/0013-service-framework.md) (accepted). The `Service` trait,
  both placements, and the CI job that builds both (this is the milestone that makes
  [architecture.md](architecture.md) §2 true rather than aspirational). Its precondition is met:
  until the bulk paths used shared memory the two placements were identical *by accident*, because
  four registers map into nobody
- **IOMMU: discovery, per-device domains, strict mapping** — [RFC 0012](rfc/0012-iommu.md)
  (accepted). VT-d first, because QEMU emulates it and a design CI cannot test will be wrong
  unnoticed; an AMD machine runs degraded and says so. This is what funds `security.md` §1 T3
  and T4, and what unblocks a driver running outside the kernel
- **Driver framework** — [RFC 0014](rfc/0014-driver-framework.md) (draft). PCIe/ECAM enumeration,
  `register_block!`, `Mmio<T>`, mock-MMIO test harness. Its motivation is an invoice rather than a
  plan: the second driver — `bin/blkd`, in a domain — cost three bugs the first one had already
  learned and written down in comments, and a framework is the difference between a lesson recorded
  and a lesson enforced
- **Networking** — virtio-net, Ethernet, ARP, IPv4/IPv6, UDP, TCP, sockets
- **Telemetry plane** ([ai-native.md](ai-native.md) §2) — built here, as the developer tracing tool
- **`bhaskixboot.efi`** — our own UEFI loader, replacing Limine behind the same `Handoff` (the
  sovereignty milestone the boot shim was designed to enable)
- **Package management** and image building
- **libc** — enough for real userspace software. Belongs to the **Linux personality**
  ([RFC 0005](rfc/0005-linux-abi-compatibility.md)), not to native userspace: RFC 0008
  is accepted, and the native ABI *is* the capability interface, so a native program
  links no libc at all. The user-mode shell at M6-05 is the demonstration — it has no
  runtime and could not have one

**Exit:** Bhaskix self-hosts its own userspace utilities, does useful network I/O, and boots on its
own bootloader.

---

## Phase 3 — Enterprise Features

- **Container runtime** — container domains, OCI image support
- **Virtual machines** — VMX/SVM, EPT/NPT, vCPU threads, virtio device backends
  (the domain abstraction from M5 is what makes this additive rather than a second kernel)
- **Storage** — volume management, snapshots, encryption at rest
- **Secure boot chain** — Secure Boot, TPM measurement, sealed keys
- **Secure update** — immutable root, A/B slots, rollback protection
- **RBAC** — `bhaskixd-authz` over capabilities
- **Audit framework** — hash-chained log over the telemetry plane, remote attestation
- **IOMMU, the rest of it** — interrupt remapping, nested translation for VMs, and AMD-Vi.
  Discovery, per-device domains and strict mapping moved to Phase 2 when
  [RFC 0012](rfc/0012-iommu.md) was accepted: they are what make a driver's mistakes
  containable, and leaving them here left `security.md` §1 T3 and T4 unfunded for the
  length of Phase 2
- **Side-channel mitigations** — the documented Phase-1/2 gap in [security.md](security.md) §1

**Exit:** a signed, attestable Bhaskix boots, runs containers and VMs side by side under one
scheduler, updates atomically, and survives an external security review of the stated threat model.

---

## Phase 4 — AI-Native Platform

Depends on the telemetry plane (Phase 2) and the policy hooks, which are added alongside their
subsystems throughout Phase 1–3 rather than retrofitted.

- `bhaskixd-ai` domain, model loading, NPU/GPU access via ordinary device capabilities
- Runtime-prediction model behind `SchedPolicy`
- Reclaim, prefetch, and I/O policy models
- Streaming anomaly detection → incident alerts
- Diagnostics: causal correlation over telemetry
- Local assistant (LLM in a capability-scoped domain)
- Bounded autonomous actions with operator-authored limits

**Exit:** measurable improvement on at least one published benchmark against the default heuristics —
**and** the degradation test passes: kill `bhaskixd-ai` mid-benchmark and the suite still completes
correctly at baseline performance.

That second criterion is the important one. A system that gets faster with AI and breaks without it
has made AI a dependency, which is exactly what [ai-native.md](ai-native.md) §0 forbids.

---

## Phase 5 — Enterprise Ecosystem

Editions are configurations of one kernel and one service set, not forks.

| Edition | Distinguishing content |
|---|---|
| **Server** | Headless, networking, containers, remote management |
| **Hypervisor** | Minimal host surface, VM domains, live migration |
| **Edge** | Small footprint, tickless, offline AI, field update |
| **Embedded** | AArch64, RT class, deterministic latency, no dynamic allocation in critical paths |
| **Desktop** | GPU (`domain` placement), compositor, audio, USB |

Desktop is deliberately last. It is the largest driver surface and the least differentiating work,
and doing it early would consume the project.

---

## How to pick up work

1. Read [vision.md](vision.md), [architecture.md](architecture.md), and
   [coding-style.md](coding-style.md).
2. Look at the current milestone above. Work outside it is welcome as an RFC, but reviewer attention
   goes to the current milestone first.
3. For anything substantial, open an RFC in `docs/rfc/` before writing code. This is not
   bureaucracy — it is the single practice that most distinguishes kernel projects that survive from
   those that do not.
4. Issues labelled `good-first-issue` are real and are kept stocked. If they run dry, that is a
   maintainer failure; say so.
