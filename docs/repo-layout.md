# Bhaskix — Repository Layout

Where things go, and — more usefully — where they must *not* go.

```
bhaskix/
├── README.md               project overview and reading order
├── AUTHORS.md              original author and contributors
├── CONTRIBUTING.md         how to contribute; RFC process; DCO
├── GOVERNANCE.md           who decides what, and how that changes
├── Cargo.toml              workspace; members added as milestones land
├── rust-toolchain.toml     pinned toolchain — do not override locally
│
├── docs/                   design documents. Written BEFORE the code they describe.
│   ├── vision.md
│   ├── architecture.md     ← everything else derives from this
│   ├── memory.md
│   ├── scheduler.md
│   ├── security.md
│   ├── driver-model.md
│   ├── ai-native.md
│   ├── coding-style.md     ← read before your first PR
│   ├── roadmap.md
│   ├── release-notes.md
│   ├── repo-layout.md      you are here
│   └── rfc/                numbered design proposals; 0000-template.md
│
├── boot/                   bootloader shim → bhaskix_boot::Handoff
│   └── limine/             Limine config and fetched binaries (gitignored)
│                           ⚠ THE ONLY PLACE THAT MAY NAME LIMINE. CI enforces this.
│
├── arch/                   architecture-specific code
│   └── x86_64/
│       ├── asm/            boot entry, context switch, interrupt stubs
│       └── src/            GDT, IDT, APIC, TSS, MSRs, CPU features, VMX
│                           ⚠ the ONLY place x86-specific instructions appear
│
├── kernel/                 the nucleus: capabilities, domains, IPC,
│                           syscall dispatch, init. Size is a budget
│                           (architecture.md §2), tracked in CI.
│
├── mm/                     physical + virtual memory, slab, address spaces, DMA
├── sched/                  runqueues, scheduling classes, balancing, policy hook
├── fs/                     VFS and filesystems (a service)
├── net/                    network stack (a service)
├── drivers/                device drivers (services), one module per device.
│                           virtio-blk is in kernel/ rather than here, which is
│                           the placement driver-model.md §6 gives it: small,
│                           performance-critical drivers default to `nucleus`.
│
├── abi/                    the interface between the kernel and the programs
│                           it runs: syscall numbers, the message layout, the
│                           methods services answer. Compiled into BOTH sides,
│                           so its `unsafe` budget is zero and stays there.
│
├── user/                   unprivileged programs. Each is its own workspace:
│   │                       they need their own code model and linker script,
│   │                       which a workspace member cannot have.
│   ├── probe/              the ring 3 probe the kernel proves user mode with
│   └── shell/              the user-mode shell (M6-05)
│
├── libc/                   userspace C runtime — Phase 2.
│                           ⚠ NEVER linked into the kernel.
│
├── userspace/              init and bhaskixd-* daemons — Phase 2. Named
│                           before `user/` existed; when the daemons arrive,
│                           one of the two names goes.
├── tools/                  setup-dev.sh, image builder, CI helpers
│
├── tests/
│   ├── unit/               host tests — allocators, page-table logic,
│   │                       schedulers, parsers, driver state machines
│   ├── integration/        cross-subsystem tests
│   └── qemu/               boot tests, frame-leak gate, RT-latency gate
│
└── .github/workflows/      CI
```

## Rules CI enforces

| Rule | Why |
|---|---|
| Only `boot/` may reference Limine | So `bhaskixboot.efi` (Phase 2) is a shim rewrite, not a kernel rewrite |
| No dependency cycles; direction is `arch → mm → sched → kernel → services` | Cycles make a kernel unbuildable in pieces and untestable in isolation |
| `unsafe` only in `arch`, `mm`, allocator internals, and each driver's `hal` | Confines the auditable surface (coding-style.md §3) |
| Every `unsafe` block has a `// SAFETY:` comment | The highest-value thing a reviewer checks |
| Per-crate `unsafe` budgets not exceeded | Makes growth visible instead of gradual |
| `libc/` is never a kernel dependency | The kernel is `no_std`; a C runtime in the nucleus is a category error |
| Every service builds in **both** placements | Keeps architecture.md §2 true rather than aspirational |

## Where does my code go?

| I am writing... | It goes in |
|---|---|
| An x86 instruction wrapper, or MSR access | `arch/x86_64/src/` |
| Anything portable that needs an x86 fact | Nowhere — add it to the `Arch` trait instead |
| A new allocator, or page-table logic | `mm/` |
| A device driver | `drivers/<device>/`, with a manifest (driver-model.md §5) |
| A filesystem | `fs/<name>/` |
| A test that needs no hardware | `tests/unit/` — **prefer this over everything below** |
| A test that needs a booted kernel | `tests/qemu/` |
| A design idea | `docs/rfc/` — before the code, not after |
