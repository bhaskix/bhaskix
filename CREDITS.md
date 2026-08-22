# Credits

Bhaskix is written from scratch, and it is not written alone.

[`AUTHORS.md`](AUTHORS.md) records who wrote the code — authorship, in the
copyright sense, under the Developer Certificate of Origin. **This page is for
the other thing**: the people whose support, encouragement and time made the
work possible, whether or not they ever opened a source file.

## Original author and project lead

**Tarun Kumar Kushwaha** — creator of Bhaskix. The project vision, the initial
architecture, and the design documents in [`docs/`](docs/).

## With thanks to

- **Professor Pawan Kumar Mall**
- **Prince Komal Boonlia**
- **Mayur Agnihotri**
- **Devesh Singh**
- **Neha Mourya**
- **the StraightArc Team**

These names are also printed by the kernel itself, in the boot banner beside the
author's, because thanks that only exist in a file nobody opens are thanks
nobody reads. See `banner()` in [`kernel/src/lib.rs`](kernel/src/lib.rs).

## How to be added here

Contributions of code are recorded in [`AUTHORS.md`](AUTHORS.md) — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how that works.

This page is different, and deliberately not automatic: it is the project
lead's to write. If someone helped and is missing, that is a bug in this file,
and the fix is a pull request that adds them.

## What this project stands on

Bhaskix is written from scratch in the sense that matters — the kernel, the
scheduler, the capability model, the filesystem, the network stack, the ELF
parser and the bootloader are this project's own code, and the shipped
workspace has **zero external runtime dependencies**.

It does not pretend to have invented the machine it runs on. The debts are
named rather than hidden:

- **UEFI firmware**, whose services the loader calls to find its payload. The
  specification requires the EFI System Partition to be FAT, which is why the
  boot medium is one — a firmware interface, not a filesystem Bhaskix
  implements. Bhaskix's own filesystem is in [`fs/`](fs/).
- **The Limine bootloader**, still the BIOS path, and replaceable by design:
  the kernel consumes `bhaskix_boot::Handoff`, a structure this project owns.
  The native UEFI loader [`bhaskixboot`](boot/bhaskixboot/) already boots the
  machine at full gate parity.
- **Adapted third-party source** in [`third_party/`](third_party/), each with
  its own `PROVENANCE.md` naming the upstream, the version, the copyright
  holder and what changed. Everything there is listed in [`NOTICE`](NOTICE).
- **The Rust toolchain and LLVM**, and the build tools — `xorriso`, `mkfs.vfat`,
  QEMU — which run on the build machine and ship nothing into the image.

Every one of those is an interface this project speaks to, or a tool that made
it, rather than a foundation holding it up.
