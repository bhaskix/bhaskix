# Bhaskix — System Architecture

*Status: draft for review. This is the document every other design document derives from.*

- **Language:** Rust (`#![no_std]`) with minimal assembly. See [coding-style.md](coding-style.md).
- **Initial target:** `x86_64`. AArch64 is a Phase 3 concern, but the arch boundary is defined now.
- **Boot:** Limine protocol on UEFI (and BIOS, free of charge). See [Boot](#1-boot-architecture).

---

## 0. The one-paragraph summary

Bhaskix is a **capability-based nucleus with relocatable services**. A small privileged core owns
physical memory, address spaces, threads, IPC, interrupt routing, and the capability system.
Everything else — VFS, network stack, device drivers, container and VM management — is a *service*
written against a message-passing interface. Services start life compiled into the nucleus for speed
and bootstrap simplicity, and can be moved into isolated userspace domains without rewriting them.
Containers and virtual machines are not separate subsystems; both are *domains*, differing only in
whether their instruction stream traps to a syscall or to a VMEXIT.

---

## 1. Boot architecture

```
UEFI firmware
   │  (verifies signature — see security.md)
   ▼
Limine  ──── loads ELF, enters long mode, builds page tables,
   │         collects memory map / framebuffer / RSDP / SMBIOS
   ▼
bhaskix_boot::Handoff   ◄── OUR struct, not Limine's
   │
   ▼
kernel::main()
```

### The handoff boundary

The kernel **never** reads a Limine request struct directly. `boot/` contains a thin shim whose only
job is to translate whatever the bootloader gave us into `bhaskix_boot::Handoff`, a struct we own and
version:

```rust
#[repr(C)]
pub struct Handoff {
    pub version: u32,
    pub memory_map: &'static [MemoryRegion],
    pub hhdm_base: VirtAddr,          // direct map of all physical memory
    pub kernel_phys_base: PhysAddr,
    pub kernel_virt_base: VirtAddr,
    pub framebuffer: Option<Framebuffer>,
    pub rsdp: Option<PhysAddr>,       // ACPI
    pub smbios: Option<PhysAddr>,
    pub boot_cmdline: &'static str,
    pub initrd: Option<PhysSlice>,
    pub tpm_event_log: Option<PhysSlice>,
}
```

This is deliberate. It costs roughly 200 lines and buys three things:

1. We can replace Limine with our own UEFI loader (`bhaskixboot.efi`, a Phase 2 milestone) by
   rewriting only the shim.
2. We can add a BIOS, coreboot, or U-Boot path later without touching the kernel.
3. The kernel is testable on the host: construct a synthetic `Handoff` and run `mm` unit tests
   without any firmware at all.

**Invariant:** nothing in `kernel/`, `mm/`, `sched/`, `fs/`, `drivers/`, or `net/` may name Limine.
CI enforces this with a grep.

### Address space layout (x86_64, 4-level paging)

| Range | Contents |
|---|---|
| `0x0000_0000_0000_1000` – `0x0000_7FFF_FFFF_FFFF` | User space (per-domain) |
| *(canonical hole)* | |
| `0xFFFF_8000_0000_0000` + | HHDM — direct map of all physical RAM |
| `0xFFFF_9000_0000_0000` + | Kernel heap (slab / vmalloc region) |
| `0xFFFF_A000_0000_0000` + | Per-CPU areas, kernel stacks (guard-paged) |
| `0xFFFF_FFFF_8000_0000` + | Kernel image (text/rodata/data/bss) |

KASLR shifts the kernel image base and the heap base at boot. LA57 (5-level) support is detected and
the layout is parameterised, but 4-level is the tested path. Details: [memory.md](memory.md).

---

## 2. The nucleus

The nucleus is the code that runs with full hardware privilege. Its size is a **budget**, not an
accident. Target: under 15,000 lines of Rust excluding architecture-specific code and comments,
tracked in CI and reported on every PR.

The nucleus owns exactly seven things:

| Subsystem | Responsibility | Explicitly *not* its job |
|---|---|---|
| **Physical memory** | Frame allocation, ownership, zeroing | Deciding what memory is *for* |
| **Address spaces** | Page tables, mapping, COW, demand paging | File-backed mapping semantics (that's VFS) |
| **Threads** | Contexts, kernel stacks, FPU state | Process/session/job concepts |
| **Scheduling** | Deciding which thread runs next on which CPU | Policy tuning heuristics (pluggable) |
| **IPC** | Synchronous call/reply + async channels | Message *content* or protocol |
| **Capabilities** | Unforgeable handles, derivation, revocation | Who *should* get what (that's policy) |
| **Interrupts & time** | IDT/APIC routing, timers, IRQ→wakeup | Device semantics (that's a driver) |

Anything that does not appear in that table does not belong in the nucleus. When someone proposes
adding to it, the burden of proof is on the proposal.

### Why not a pure microkernel, and why not a monolith

A pure microkernel (seL4-style) is the honest expression of "security by design", but it makes early
progress slow, pushes hard performance problems to the front of the schedule, and historically
starves such projects before they get useful. A monolith gets to a working system fastest and throws
the security thesis away.

We take a third path and are explicit about its risk.

### Relocatable services — the design, and its honest caveat

A **service** is a Rust crate that implements `Service` and communicates only by messages. The build
selects a placement per service:

```
[services]
vfs      = "nucleus"     # trusted, in-kernel, direct call — fast path
netstack = "nucleus"
nvme     = "nucleus"
gpu      = "domain"      # isolated userspace domain, IPC + IOMMU
```

For this to work, a service must obey four rules, enforced by the crate's lint configuration:

1. No global mutable state. All state hangs off the service's own context object.
2. No direct hardware access. MMIO, DMA, and IRQs arrive only through capability handles.
3. No blocking calls. Services are `async` state machines driven by an executor the placement
   provides.
4. No panics on input. Malformed messages return errors; they do not unwind.

**The caveat, stated plainly:** "write once, place anywhere" is a claim many systems have made and
few have delivered. The usual failure is that in-nucleus services quietly acquire direct calls,
shared statics, and pointer-passing, and the userspace placement rots. Our mitigations are (a) CI
builds *both* placements for every service on every PR, and (b) the QEMU test suite runs the full
boot with all services forced to `domain`. If we ever cannot afford to keep both placements green,
we will say so in this document rather than quietly dropping the goal.

---

## 3. Capabilities

There is no user ID in the nucleus. There is no `root`. Authority is a *thing you hold*, not a *thing
you are*.

Every kernel object — a frame, an address space, a thread, an IPC endpoint, an IRQ line, an MMIO
range, a DMA window — is named by a **capability**: an unforgeable handle stored in a per-domain
capability space (CSpace). A domain can perform an operation if and only if it holds a capability
granting it.

```
Capability {
    object:  ObjectRef,      // what
    rights:  Rights,         // read | write | execute | grant | revoke | derive
    badge:   u64,            // caller identity, set by the granter, unforgeable by the holder
}
```

Properties we commit to:

- **Derivation is monotone.** A derived capability never has rights the parent lacked.
- **Revocation is transitive and immediate.** Revoking a capability revokes everything derived from
  it, before the revoke syscall returns.
- **Badges are set by the granter.** A service can therefore identify its callers without trusting
  them, which is what makes RBAC implementable in userspace.

Role-based access control (Phase 3) is a userspace policy service that hands out capabilities. It is
built *on* this mechanism, not *instead of* it. Details: [security.md](security.md).

---

## 4. Domains: containers and VMs are the same thing

A **domain** is the unit of isolation, accounting, and scheduling:

```
Domain {
    cspace:     CSpace,            // what it may touch
    aspace:     AddressSpace,      // where it may touch it  (page table OR EPT/NPT)
    threads:    Vec<Thread>,
    envelope:   ResourceEnvelope,  // cpu shares, memory limit, io weight, latency class
    telemetry:  TelemetryChannel,  // see ai-native.md
}
```

The only difference between a container and a virtual machine:

|  | Container domain | VM domain |
|---|---|---|
| Address space | Ordinary 4-level page table | EPT (Intel) / NPT (AMD) |
| Entry to kernel | `SYSCALL` → syscall dispatch | `VMEXIT` → exit handler |
| Services seen | Host VFS / netstack via IPC | Virtual devices via virtio, backed by the same services |
| Scheduling | Threads on host runqueues | vCPU threads on host runqueues |

This is the concrete meaning of "virtualization as a first-class capability". The scheduler,
accounting, memory reclaim, and telemetry paths do not know or care which kind of domain they are
serving. There is no separate hypervisor codebase to keep in sync, and a container escape and a VM
escape land in the same place: a domain with no capabilities.

Hardware virtualization (VMX/SVM) is a Phase 3 milestone. The domain abstraction is defined now so
that nothing built in Phase 1 or 2 has to be undone to accommodate it.

---

## 5. Crate layout

```
bhaskix/
├── boot/            bootloader shim → bhaskix_boot::Handoff  (the ONLY crate that knows Limine)
├── arch/x86_64/     GDT, IDT, APIC, TSS, MSRs, context switch asm, VMX stubs
├── kernel/          the nucleus: caps, domains, IPC, syscall dispatch, init
├── mm/              physical + virtual memory, slab, address spaces
├── sched/           runqueues, scheduling classes, load balancing, policy trait
├── fs/              VFS + filesystem implementations (service)
├── net/             network stack (service)
├── drivers/         device drivers (services)
├── libc/            userspace C runtime — Phase 2, NOT used by the kernel
├── userspace/       init, shell, bhaskixd-* daemons
├── tools/           build tooling, image builder, dev setup
├── tests/           unit, integration, and QEMU boot tests
└── docs/            you are here
```

Dependency rule, enforced in CI:

```
arch  →  (nothing)
mm    →  arch
sched →  arch, mm
kernel→  arch, mm, sched
fs, net, drivers  →  kernel  (via the service interface only)
```

Cycles are a build failure, not a review comment.

---

## 6. Concurrency model

- **SMP from the start.** Single-CPU-only shortcuts are technical debt with a long tail; we do not
  take them. Bring-up is single-CPU, but no data structure assumes it.
- **No sleeping in interrupt context.** IRQ handlers do the minimum and wake a thread. Enforced by
  a marker type: functions that may sleep take `&mut SleepGuard`, which IRQ context cannot produce.
- **Lock ordering is declared, not remembered.** Every lock has a static rank, given at construction
  so it cannot be omitted; blocking on a lock at or inside one already held is reported and counted,
  and a non-zero count fails the boot test. This kills the entire class of deadlock bugs that eats
  kernel projects at month six. `try_lock` is exempt, because a non-blocking acquisition cannot be
  an edge in a deadlock cycle — which is what makes locking from interrupt context expressible at
  all. Implemented at M4-08; the rank list is in `kernel/src/sync.rs` and
  [coding-style.md](coding-style.md) §7 records where it deviates from the original rule.
- **Prefer per-CPU over shared.** Then RCU-style read-mostly structures. Then locks. In that order.
- **`async` for I/O paths**, plain blocking threads for compute. Drivers are `async`.

---

## 7. Architecture abstraction

`arch/` exposes a trait-shaped interface that the portable crates program against:

```rust
pub trait Arch {
    type PageTable: PageTableOps;
    type Context:   ThreadContext;
    fn enable_interrupts();
    fn disable_interrupts() -> IrqState;
    fn context_switch(from: &mut Self::Context, to: &Self::Context);  // asm
    fn flush_tlb(range: VirtRange, asid: Option<Asid>);
    fn cpu_id() -> CpuId;
    /* ... */
}
```

We commit to *defining* this boundary before a second architecture exists. Retrofitting
portability into a kernel that assumed one architecture is a rewrite; keeping a second
implementation honest from the start is a chore, and we choose the chore.

**Revised at M2 (2026-08-03):** the trait was originally scheduled for M2 and has been deferred.
Writing a portability boundary with exactly one implementation and no second architecture in sight
produces a trait shaped like x86 — it would document today's code rather than constrain tomorrow's,
which is the opposite of the point. The concrete boundary that matters now is enforced instead:
architecture-specific instructions appear only in `arch/`, and CI checks the dependency direction.
The trait will be defined when AArch64 work begins, which is when there is a second implementation
to keep it honest.

---

## 8. Open decisions

These are unresolved and should not be silently settled in code. Each needs an RFC.

| # | Decision | Notes |
|---|---|---|
| ~~A1~~ | ~~License~~ | ✅ **Resolved 2026-08-02: Apache-2.0.** Permissive for enterprise and government adoption, with the explicit patent grant that MIT lacks. See [RFC 0001](rfc/0001-license-apache-2.0.md) for the rejected alternatives. |
| A2 | Syscall ABI shape | Capability-invocation only (seL4-like, small and uniform) vs a broader numbered syscall table (familiar, easier to port software to). |
| A3 | IPC style | Synchronous rendezvous (simple, fast, easy to reason about) vs async channels with buffering (better for `async` services, harder to bound memory). Likely both, but which is primitive? |
| A4 | Userspace ABI | Our own from scratch vs POSIX-shaped in `libc/`. Determines how much existing software can ever be ported. |
| A5 | 5-level paging | Support LA57 from day one, or assume 4-level and parameterise later? |

---

## 9. Reading order for new contributors

1. [vision.md](vision.md) — why this exists
2. this document — how it fits together
3. [memory.md](memory.md) — the first subsystem you will touch
4. [coding-style.md](coding-style.md) — before you open a PR
5. [roadmap.md](roadmap.md) — what to pick up
