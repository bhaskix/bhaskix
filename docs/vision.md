# Bhaskix — Vision

*Status: adopted. Changes to this document require a governance decision.*

## Vision

To build the world's first open-source, AI-native, enterprise operating system from India — designed
for cloud infrastructure, virtualization, cybersecurity, edge computing, and autonomous operations.

Bhaskix is not a Linux distribution. It is built around its own kernel, designed from the ground up
with security, virtualization, scalability, and artificial intelligence as core architectural
principles rather than optional additions.

The project is fully open source, community-driven, and focused on long-term sustainability.

## Mission

Build a modern operating system that enables developers, enterprises, and governments to deploy
secure and intelligent computing infrastructure without depending on proprietary operating systems.

## Core Principles

These are not slogans. Each one is testable, and each one has a document that explains how we hold
ourselves to it.

| Principle | What it actually means | Enforced by |
|---|---|---|
| Build our own kernel | No forked kernel, no Linux compatibility layer in the nucleus. External code is confined to the bootloader and to optional userspace. | [architecture.md](architecture.md) |
| Security by design, not by addition | No ambient authority. A component can only touch what it holds a capability for. There is no `root`. | [security.md](security.md) |
| AI integrated into system operations | The kernel emits typed telemetry and accepts *advice* on pluggable policies. The model advises; the kernel decides. | [ai-native.md](ai-native.md) |
| Virtualization as a first-class capability | Containers and virtual machines are the same primitive — a *domain*. Isolation is not retrofitted onto processes. | [architecture.md](architecture.md) |
| Cloud and distributed systems ready | Immutable images, atomic A/B updates, attestable boot, declarative configuration. | [security.md](security.md) |
| Open standards wherever possible | UEFI, ACPI, ELF, virtio, NVMe, TCP/IP, OCI. We invent an interface only when no open one fits. | [driver-model.md](driver-model.md) |
| Community-first development | Design documents and RFCs precede implementation. Every line is written in public. | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Transparent governance | Decisions, and the reasoning behind rejected alternatives, are recorded. | [../GOVERNANCE.md](../GOVERNANCE.md) |

## Phases

Phases describe *capability*, not dates. See [roadmap.md](roadmap.md) for the milestone breakdown
and exit criteria.

1. **Foundation** — UEFI boot, 64-bit kernel, physical and virtual memory management, scheduler,
   system calls, basic filesystem, kernel shell.
2. **Core Operating System** — process management, user mode, ELF loader, virtual filesystem,
   networking, driver framework, package management.
3. **Enterprise Features** — container runtime, virtual machine integration, storage management,
   secure update mechanism, role-based security, audit framework.
4. **AI-Native Platform** — local AI assistant, AI-powered diagnostics, intelligent scheduling,
   predictive resource optimization, automated incident detection, autonomous system management.
5. **Enterprise Ecosystem** — desktop, server, hypervisor, edge, and embedded editions.

## Open Source Philosophy

Every line of code is developed in public.

Contributors from around the world are encouraged to participate through open discussions,
transparent design documents, public roadmaps, and community-led reviews.

The objective is not merely to create another operating system, but to establish a long-term systems
software ecosystem originating from India and supported by a global community.

## What Success Means

Success is not measured by replacing Linux.

Success is measured by building a technically respected operating system that advances kernel
engineering, systems security, virtualization, and AI while inspiring a new generation of
open-source contributors.

Concretely, we will consider the project successful when:

- A person who has never written kernel code can build, boot, and modify Bhaskix in under an hour.
- A security researcher can read [security.md](security.md), attack the stated threat model, and
  find the document honest.
- At least one design idea from Bhaskix is cited or adopted outside this project.
- The project survives the departure of any single contributor, including its founder.

## What Success Does Not Mean

Stating the anti-goals is as important as stating the goals.

- **Not** binary compatibility with Linux. We may add a translation layer in userspace much later;
  it will never be a nucleus concern.
- **Not** a package count race. A small, coherent, well-maintained system beats a large one.
- **Not** shipping AI features that cannot be turned off, audited, or run offline.
- **Not** a benchmark-first project. Correctness and clarity come first; performance work follows
  measurement, not intuition.
