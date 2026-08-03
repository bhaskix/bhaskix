# Bhaskix

**An open-source, AI-native, enterprise operating system — built from scratch, from India.**

Bhaskix is not a Linux distribution. It is a new operating system built around its own kernel,
designed from the ground up with security, virtualization, scalability, and artificial intelligence
as core architectural principles rather than optional additions.

**Bhaskix** — from *bhāskara* (भास्कर), Sanskrit for "the light-maker", the sun; and the name of two
of India's great mathematician-astronomers. Bhāskara I (c. 600–680 CE) was the first person known to
have written Hindu-Arabic numerals with a circle for zero, and gave a rational approximation of the
sine function that stood for centuries. Bhāskara II (1114–1185) worked out results in what would
later be called calculus, five hundred years before Newton and Leibniz.

The `-ix` is the Unix lineage, the same suffix Minix and Linux carry.

> **Status: M1 — it boots.**
> Bhaskix boots on UEFI and BIOS, brings up a serial and framebuffer console, and prints its
> memory map. It is not yet an operating system: there are no interrupts, no memory manager, no
> processes. See [TRACKER.md](TRACKER.md) for exactly what works and what is not yet proven.
>
> The design documents were written first, deliberately: kernel projects that begin with a clear
> architecture evolve; those that begin with code rewrite.

---

## Why another operating system

Every general-purpose operating system in production today was architected before containers,
before ubiquitous virtualization, before hardware memory-safety was practical, and before machine
learning could inform system decisions. Each has retrofitted these things well. None was designed
around them.

Bhaskix asks what an operating system looks like if those are assumptions rather than additions:

- **Capabilities instead of `root`.** There is no ambient authority. A component touches what it
  holds a capability for, and nothing else. Whole classes of privilege escalation stop being
  expressible. → [docs/security.md](docs/security.md)
- **Containers and VMs are the same primitive.** Both are *domains*. One scheduler, one accounting
  path, one isolation mechanism — no separate hypervisor codebase drifting out of sync.
  → [docs/architecture.md](docs/architecture.md)
- **Drivers are contained by default.** Every driver gets a capability to exactly one device, and its
  DMA is bounded by the IOMMU — even when compiled into the kernel.
  → [docs/driver-model.md](docs/driver-model.md)
- **The kernel is observable by construction.** Typed, causal, per-CPU telemetry of the kernel's own
  decisions — which is what makes AI-assisted operation possible, and what makes debugging bearable.
  → [docs/ai-native.md](docs/ai-native.md)
- **The model advises; the kernel decides.** AI policies rank options the kernel has already ruled
  legal, under a hard time budget, always with a working default underneath. Kill the AI daemon and
  the system keeps running. → [docs/ai-native.md](docs/ai-native.md)
- **Written in Rust.** Memory safety as a structural property, with every `unsafe` block justified,
  reviewed, and budgeted. → [docs/coding-style.md](docs/coding-style.md)

## Design documents

Read in this order:

| Document | What it covers |
|---|---|
| [docs/vision.md](docs/vision.md) | Why this project exists, and what success and failure look like |
| [docs/architecture.md](docs/architecture.md) | Nucleus, services, capabilities, domains, crate layout |
| [docs/memory.md](docs/memory.md) | Physical and virtual memory, kernel heap, DMA and IOMMU |
| [docs/scheduler.md](docs/scheduler.md) | Runqueues, scheduling classes, SMP balancing, context switch |
| [docs/security.md](docs/security.md) | Threat model — including what we explicitly do *not* defend against |
| [docs/driver-model.md](docs/driver-model.md) | Driver isolation, MMIO typing, enumeration, testing without hardware |
| [docs/ai-native.md](docs/ai-native.md) | Telemetry plane, policy hooks, where inference runs — and what we refuse to build |
| [docs/coding-style.md](docs/coding-style.md) | Engineering rules. Read before your first PR. |
| [docs/roadmap.md](docs/roadmap.md) | Milestones and their verifiable exit criteria |

## Technical summary

| | |
|---|---|
| Language | Rust (`no_std`, edition 2024) + minimal assembly |
| Architecture | `x86_64` first; the arch boundary is defined now, AArch64 in Phase 3 |
| Boot | UEFI via the Limine protocol, behind our own `Handoff` struct; native `bhaskixboot.efi` in Phase 2 |
| Kernel model | Capability-based nucleus with relocatable services |
| Isolation | Domains — containers and VMs are the same primitive |
| License | **Apache-2.0** — see [LICENSE](LICENSE) and [RFC 0001](docs/rfc/0001-license-apache-2.0.md) |

## Building

```sh
tools/setup-dev.sh      # rust toolchain, qemu, limine, xorriso, ovmf
make                    # build the kernel and a bootable ISO
make run                # boot it in QEMU (BIOS)
make run-uefi           # boot it in QEMU (UEFI, via OVMF)
make test               # everything CI runs -- about 80 seconds
```

Builds on **stable Rust** — no nightly, no `#![feature]` anywhere in the tree
(see [docs/nightly-features.md](docs/nightly-features.md)). Verified with Rust
1.90.0, QEMU 4.2.1, and Limine 8.7.0.

`make test` runs, in order: `rustfmt`, `clippy` on both the freestanding and
host targets, 17 host unit tests, three project-invariant gates (bootloader
containment, `unsafe` budgets with mandatory `// SAFETY:` justifications,
dependency direction), and BIOS + UEFI boot tests that assert on captured
serial output.

## Contributing

Every line of Bhaskix is developed in public. Contributors from anywhere are welcome.

Right now the most valuable contribution is **review of the design documents** — particularly
[docs/security.md](docs/security.md) §1 (is the threat model honest?) and the open decisions in
[docs/architecture.md](docs/architecture.md) §8. Finding a flaw in a document costs an afternoon.
Finding the same flaw in Phase 3 costs a year.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md).

## Authors

Created and maintained by **Tarun Kumar Kushwaha** — original author and project lead.

See [AUTHORS.md](AUTHORS.md) for all contributors.

## Prior art and acknowledgement

Bhaskix learns from work that came before it, and says so. seL4 for capability systems and the
discipline of proving what you claim. Linux for two decades of evidence about what scales and what
does not. Redox and the Rust OSDev community for showing that a Rust kernel is practical. Fuchsia
for taking capabilities into a general-purpose system. xv6 and the OSDev wiki for teaching most of
us how any of this works.

Originality is in the synthesis and in the execution, not in pretending to have invented the field.
