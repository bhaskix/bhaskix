# Bhaskix

**An open-source, AI-native, enterprise operating system — built from scratch, from India.**

Bhaskix is not a Linux distribution. It is a new operating system built around its own kernel,
designed from the ground up with security, virtualization, scalability, and artificial intelligence
as core architectural principles rather than optional additions.

**A direction under consideration: run the Linux software ecosystem without being Linux.** Linux
has accumulated powerful security mechanisms around a mature traditional architecture; Bhaskix
explores what becomes possible when authority, isolation, service separation and device
containment are architectural primitives from the first line. Compatibility would be an *adapter
above* Bhaskix's own services — never a Linux kernel underneath, and never a reason to reproduce
Linux's kernel architecture inside Bhaskix. Two properties have to survive that path or it is not
worth having: Linux `root` is not Bhaskix authority, and a compromised Linux application is not a
compromised system. → [RFC 0031](docs/rfc/0031-linux-compatibility-as-an-adapter.md), a draft

> **A direction, not a commitment — and today it runs a static Go binary and nothing larger.** No
> shell utility, web server or database has ever run here. The milestones are written down as
> [L1–L4](docs/roadmap.md#linux-compatibility--l1-to-l4), every one of them unmet, and nothing in
> this repository will say otherwise before a test proves it.

**Bhaskix** — from *bhāskara* (भास्कर), Sanskrit for "the light-maker", the sun; and the name of two
of India's great mathematician-astronomers. Bhāskara I (c. 600–680 CE) was the first person known to
have written Hindu-Arabic numerals with a circle for zero, and gave a rational approximation of the
sine function that stood for centuries. Bhāskara II (1114–1185) worked out results in what would
later be called calculus, five hundred years before Newton and Leibniz.

The `-ix` is the Unix lineage, the same suffix Minix and Linux carry.

**Created and developed by [Tarun Kumar Kushwaha](AUTHORS.md)** — original author and project lead.

> **Status: Phase 2 — core operating system.** Phase 1 is complete: M1 through M6, and M7 through
> M9 on top of them.
>
> Boots on UEFI and BIOS. Every CPU exception produces a decoded diagnostic instead of a triple
> fault. A buddy physical allocator and a slab heap; address spaces with W^X by construction;
> demand paging and copy-on-write. Threads across four CPUs with per-CPU runqueues, a fair class
> and tickless idle. Ring 3, `SYSCALL`/`SYSRET`, and capabilities with transitive revocation.
> Synchronous IPC with badges, shared memory, notifications, and interrupts delivered to a domain.
> An IOMMU giving a device its own translations. A journalled, writable filesystem with a page
> cache. Process management that is capability-shaped rather than POSIX-shaped: no `fork`, no pid,
> no signals — a **supervisor in ring 3** creates a domain, grants it authority one piece at a time,
> starts a program in it, and reaps it. And a **user-mode shell** that reaches all of it through
> capabilities it holds and nothing else — the block driver, the console, and the filesystem each
> run as services in their own domains, outside the kernel.
>
> **What is not here.** **This paragraph was stale on three counts until 2026-08-23**, and said so
> about things that had shipped four to six days earlier — IPv6, a sockets API and package
> management. All three are done: [RFC 0029](docs/rfc/0029-ipv6.md) landed IPv6 as a second address
> family on 2026-08-18 with both families measured on one boot, `bhaskix-sock` has been the sockets
> API since 2026-08-17, and packages install, run and remove at the shell with manifest-derived
> grants since 2026-08-19. Networking itself has been real since 2026-08-15: a virtio-net driver, a
> protocol service and a TCP service, each in its own domain, carry a byte stream both directions
> through rings the connecting *program* owns and hands over as capabilities, with the cost measured
> rather than argued about.
>
> What is genuinely not here: **no libc and no self-hosting** — the Linux personality runs Go
> binaries in ring 3 but its file and socket tiers are not started. **No cryptography at all**; a
> grep for eleven primitive names returns nothing, and where it will come from is a decision RFC
> that has not been adopted. **USB is a keyboard and nothing else** — no storage, no hubs, no USB 3
> — and a machine with no i8042 *and no IOMMU* still has no keyboard, because a bus master nothing
> translates for is refused rather than driven. The ELF
> loader has had its 24 hours of fuzzing, as of 2026-08-13, with no crash and no artifact. **It has
> booted on physical hardware exactly once, and every measurement above is still QEMU** — on
> 2026-08-22 the image booted on a Lenovo ThinkSystem SR550 from media mounted over its BMC,
> observed on screen. Nothing was captured: the output reached the framebuffer and not
> serial-over-LAN, so no boot report was read and no self-test result from real hardware is known.
> M1-17 stays open, because the criterion is a boot somebody read, not a boot somebody saw. Nothing
> here should run anywhere that matters — see [SECURITY.md](SECURITY.md).
>
> **The design documents still have one author and no independent reviewers.** Phase 0's exit
> criterion asks for two people who did not write them, and that is genuinely unmet rather than
> quietly marked done.
>
> [TRACKER.md](TRACKER.md) is the single source of truth for what is *proven* versus what merely
> compiles, and it records the gaps rather than hiding them. This block is a summary of it; where
> they disagree, TRACKER wins.
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

## The book

***Mastering Bhaskix***, by Tarun Kumar Kushwaha — a worked account of building
this system, organised around the method rather than the module list. It lives in
this repository so that a change to the system and the change to the book that
describes it land together.

**Scoped, one chapter of thirty-six written.** Do not expect a book yet.

| | |
|---|---|
| [book/](book/) | What has been written. Today: one chapter, *What a capability is* |
| [docs/ebook-mastering-bhaskix.md](docs/ebook-mastering-bhaskix.md) | The scope and the full chapter plan — what each chapter may claim, and the evidence in this tree that carries it |

## Technical summary

| | |
|---|---|
| Language | Rust (`no_std`, edition 2024) + minimal assembly |
| Architecture | `x86_64` only. **AArch64 is Phase 5**, in the Embedded edition — this row said Phase 3 until 2026-08-20, which [roadmap.md](docs/roadmap.md) has never said. The portability boundary is enforced in CI: the crate dependency direction, and **where an architecture-specific instruction may appear** — every crate holding one declares an `asm_budget` with its reason. The `arch::Arch` trait is **deliberately not written** until a second implementation exists to keep it honest |
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
make test               # everything CI runs -- about six minutes
```

Builds on **stable Rust** — no nightly, no `#![feature]` anywhere in the tree
(see [docs/nightly-features.md](docs/nightly-features.md)). Verified with Rust
1.97.1, QEMU 4.2.1, and Limine 8.7.0.

`make test` runs, cheapest first, so a trivial mistake fails in seconds rather
than after a QEMU boot: `rustfmt`; `clippy` on both the freestanding and host
targets; **346 host assertions**; the project-invariant gates (bootloader
containment, `unsafe` budgets with mandatory `// SAFETY:` justifications,
dependency direction, service placements, no vendor strings, SPDX headers);
BIOS, UEFI and IOMMU boot tests asserting on captured serial output across four
service placements, plus a run with the IOMMU turned off at the command line to
prove that escape hatch escapes; four modes of an **interactive shell test that
types at the machine** and reads what comes back; and a fault-injection run that
triggers six CPU exceptions and checks each is reported rather than
triple-faulting. Any `FAILED` the kernel prints fails the run, whether or not a
gate was looking for that particular one.

That is **601 checks**. A gate that has never been watched failing is not
counted as a gate here — see [TRACKER.md](TRACKER.md), which records the ones
that turned out to prove nothing and what was done about them.

## Contributing

Every line of Bhaskix is developed in public. Contributors from anywhere are welcome.

Right now the most valuable contribution is **review of the design documents** — particularly
[docs/security.md](docs/security.md) §1 (is the threat model honest?) and the open decisions in
[docs/architecture.md](docs/architecture.md) §8. Finding a flaw in a document costs an afternoon.
Finding the same flaw in Phase 3 costs a year.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md).

**Found a security bug?** Do not open a public issue — see
[SECURITY.md](SECURITY.md). Note that Bhaskix is pre-alpha and documents its
unfinished work openly, so check what is already tracked as unimplemented
before reporting.

## Authors

Created and maintained by **Tarun Kumar Kushwaha** — original author and project lead.

See [AUTHORS.md](AUTHORS.md) for all contributors, and [CREDITS.md](CREDITS.md) for the people
whose support made the work possible.

## Prior art and acknowledgement

Bhaskix learns from work that came before it, and says so. seL4 for capability systems and the
discipline of proving what you claim. Linux for two decades of evidence about what scales and what
does not. Redox and the Rust OSDev community for showing that a Rust kernel is practical. Fuchsia
for taking capabilities into a general-purpose system. xv6 and the OSDev wiki for teaching most of
us how any of this works.

Originality is in the synthesis and in the execution, not in pretending to have invented the field.
