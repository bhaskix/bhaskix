<!-- SPDX-License-Identifier: Apache-2.0 -->

# What Bhaskix is

**Verified** 2026-10-30 against `6150ade`: every claim checked against `TRACKER.md`, the README
and the boot report at that commit.

Bhaskix is a new operating system with its own kernel, written in Rust. It is
**not a Linux distribution**, and not a Linux kernel with a new layer on top.
It is a capability-based nucleus — a small kernel that decides who may do what
— with drivers, filesystems and networking running as ordinary programs, each
in a compartment of its own. Linux programs run beside them, through an adapter
that translates what they ask for.

It is a **developer preview**: something to boot, read and take apart, not
something to rely on. This page says what it does today, what it does not, and
how it differs from what you may know.

## What it does today

Each of these is checked on every boot by the machine itself, in the boot
report, or by the project's test suite (2,314 checks and 1,450 host tests in
one run on 2026-10-29):

- **It boots** on UEFI and BIOS, through Limine or through its own UEFI loader,
  `bhaskixboot.efi`, which also checks a signature over what it starts.
- **It runs on one physical server**, a Lenovo ThinkSystem SR550, to its shell —
  last on 2026-10-30 — and everywhere else in QEMU.
- **Programs hold capabilities and nothing else.** There is no `root`, no
  superuser and no global file namespace; a program can reach exactly what it
  was handed.
- **Services run in their own domains**: the console, the disks, the
  filesystem, the network and the Linux adapter are each a program in a
  compartment of its own, not code inside the kernel.
- **A journalled, writable filesystem**, a page cache, an IOMMU that confines
  each device, IPv4 and IPv6 with UDP and TCP, and packages installed at the
  shell.
- **Linux programs run, unmodified**, when they are static x86-64 binaries: a Go
  `net/http` server serving sixteen clients, and BusyBox's `sh`.
- **The boot is measured** into the machine's TPM, and the native loader checks a
  signature over the kernel, the initrd and the command line.

## What it does not do yet

Stated as plainly as the above, because a reader deciding whether to spend an
afternoon here deserves to know:

- **There is no installer.** Nothing writes Bhaskix to a disk; it boots from an
  ISO, a USB stick or a server's virtual CD, and leaves the machine as it found
  it. [Run it on a real machine](real-hardware.md) says how.
- **It is not self-hosting**: it cannot build itself.
- **It has run on one physical machine.** On that one, its disks sit behind a
  RAID controller Bhaskix does not drive, and its network answers a ping but
  gets no address and opens no TCP connection.
- **Linux programs are limited** to static x86-64 binaries without AVX: no
  dynamic linking, and no database has ever run here. The Linux-compatibility
  milestones, L1 to L4, are all unmet.
- **The project's own signing keys do not exist yet.** The developer preview's
  loader trusts no key; you can sign your own boot today
  ([Sign your own boot](secure-boot.md)).
- **No containers or virtual machines yet.** Bhaskix is designed so that both
  are the same thing — a domain — but neither is built.
- **No graphical desktop**, and no plan for one in the preview.

## How it differs from Linux

| You may expect | In Bhaskix |
|---|---|
| A `root` user who may do anything | No such user. A program's authority is the capabilities it holds, and nothing grants more |
| One file tree every program can see | A program sees the directories it was handed, and cannot climb out of them |
| Drivers inside the kernel | Drivers are programs in their own domains, each device confined by the IOMMU |
| A shell like `bash` | A small shell with its own commands; Linux's `sh` runs as a hosted program |
| `fork`, pids and signals in the kernel | The kernel has none of them; the Linux adapter builds them for the Linux programs it hosts |

Familiar names are kept where they help — `ls`, `cat`, `pkg install` — but a
familiar name never promises Linux behaviour: `ls` here lists a directory you
hold, and nothing above it.

## Where to go next

- [Get started](get-started.md) to boot it in QEMU.
- [How Bhaskix works](how-it-works.md) for the ideas behind it.
- [Questions and answers](faq.md) for the short version of everything above.
