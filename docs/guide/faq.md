<!-- SPDX-License-Identifier: Apache-2.0 -->

# Questions and answers

**Verified** 2026-10-30 against `6150ade`: each answer checked against the document it names.

Short answers, each checked against the project's own documents on the date
above; the longer answers are linked.

## Is Bhaskix Linux?

**No.** It has its own kernel, written from scratch in Rust, and its own
interfaces. It is not a Linux distribution, and there is no Linux kernel
underneath it. It can run some Linux programs through an adapter — see the next
question — but that adapter is a program running on Bhaskix, not part of it.
[What Bhaskix is](overview.md) says more.

## Can it run my Linux programs?

**Some, today.** Static x86-64 Linux binaries run unmodified when they keep to
what the adapter answers: a Go `net/http` server serving sixteen clients, and
BusyBox's `sh`, run on every test run. Dynamically linked programs, programs
built for AVX-capable CPUs (x86-64-v3) and databases do not run yet. The
compatibility milestones, L1 to L4, are all unmet; [Linux programs](linux-programs.md)
shows what runs and what is refused.

## Can I install it?

**Not to a disk.** There is no installer; Bhaskix boots from an ISO in QEMU, from
a USB stick, or from a server's virtual CD, and runs from memory.
[Run it on a real machine](real-hardware.md) says how, and what it writes (only
the project's own test disks).

## Is it ready for production?

**No.** It is a developer preview: something to boot, read and take apart. Its
security, its hardware support and its Linux compatibility each have stated
gaps, listed in [What Bhaskix is](overview.md) and
[The security model](security-model.md).

## When is the first release?

The first developer preview, `v0.1.0-preview`, is planned for **29 November
2026**: an ISO, Bhaskix's own UEFI loader, and a [release note](../release-notes.md)
that states the gaps as plainly as the features. Until then, `main` is what
these pages describe.

## What hardware does it run on?

In **QEMU**, and on **one physical server**, a Lenovo ThinkSystem SR550, to its
shell. No other physical machine has been tried. What works on that one, and
what does not, is in [Run it on a real machine](real-hardware.md#what-hardware-is-known).

## Is there a graphical desktop?

**No**, and none is planned for the preview. Bhaskix draws its console on the
screen and on the serial port.

## Why capabilities instead of users and permissions?

Because a program should be able to do what it was given and nothing more. With
users and permissions, every program a user runs can do everything that user
can; here, a program holds a capability for each thing it may use, and there is
no `root` to become. [The security model](security-model.md) explains it.

## Where does AI come in?

Bhaskix is designed so that a model **may advise and the kernel decides**: there
is no inference in the kernel, ever. The telemetry plane a model would read is
built; nothing that uses a model is.

## What is the licence?

**Apache-2.0**, for all of it. Third-party components the project fetches are
listed, with their own licences, in `NOTICE`.

## Who makes it?

It was created by **Tarun Kumar Kushwaha**, its original author and project
lead, who decides its direction (`GOVERNANCE.md`). The project accepts
contributions from anyone.

## How do I contribute?

Read `CONTRIBUTING.md`. Bug fixes, tests and documentation can be proposed
directly; a substantial change — a new subsystem, a change to a documented
invariant, a new dependency — starts as an RFC in `docs/rfc/`. Every commit is
signed off under the Developer Certificate of Origin; no copyright assignment is
asked.

## How do I report a bug?

On [GitHub](https://github.com/bhaskix/bhaskix/issues), with what you booted and
the red lines from its boot report — [Troubleshooting](troubleshooting.md#report-a-problem)
lists what helps. A **security** problem goes privately, as `SECURITY.md`
describes.

## Why is it called Bhaskix?

From *bhāskara* (भास्कर), Sanskrit for "the light-maker", the sun, and the name of
two of India's great mathematician-astronomers; the `-ix` is the Unix lineage,
the suffix Minix and Linux carry.
