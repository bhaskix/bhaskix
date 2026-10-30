<!-- SPDX-License-Identifier: Apache-2.0 -->

# Build from source

**Verified** 2026-10-30 against `aa2dcc5`, in a fresh clone from GitHub on Ubuntu 20.04, by running
every command shown; `make demo`'s leaving key against `6150ade`.

This page builds Bhaskix from a checkout, boots what it built, and runs the
project's own tests. If you only want to try it, [Get started](get-started.md)
boots the release without building anything.

## What you need

- **An x86-64 Linux machine.** These steps were run on Ubuntu 20.04; the
  project's CI builds on Ubuntu 26.04.
- **Disk:** a build uses a few hundred megabytes; the full test suite about 3 GB.
- **Git**, to fetch the source, and **a C compiler** (`gcc`): the setup script
  builds Limine's small installer with it, and `--check` does not look for one.

Everything else — Rust at the version the tree pins, QEMU, xorriso, mtools, the
Limine bootloader and OVMF — is installed or checked by one script.

## Get the source and the tools

```sh
git clone https://github.com/bhaskix/bhaskix.git
cd bhaskix
tools/setup-dev.sh --check
```

`--check` reports what is missing and installs nothing:

```
==> Checking host packages
  [ok]   curl
  [ok]   make
  [ok]   xorriso
  [ok]   mformat
  [ok]   git
  [ok]   qemu-system-x86_64
==> Checking Rust toolchain
  [ok]   rustup
==> Checking Limine bootloader
  [need] limine (v8.x-binary)
==> Checking UEFI firmware (OVMF) for QEMU
  [ok]   OVMF

==> Missing 1 item(s). Re-run without --check to install.
```

Run it without `--check` to install what it lists. On Debian and Ubuntu it
installs system packages with `sudo apt-get install -y` — it does not ask first,
so read the `--check` list before you run it; on other distributions it stops
and prints the packages to install by hand. It never removes anything and is
safe to run again. Rust
comes from `rustup`, at the version `rust-toolchain.toml` names — **stable
Rust**: nothing in the tree needs nightly to build.

## Build it

```sh
make
```

That builds the kernel, its services and the ISO. On a fresh clone it took 67
seconds on the machine these pages were checked on, and ended:

```
…
xorriso 1.5.2 : RockRidge filesystem manipulator, libburnia project.
boot/limine/limine/limine bios-install build/bhaskix.iso 2>/dev/null
built build/bhaskix.iso
```

What it made, and where:

| File | What it is |
|---|---|
| `build/bhaskix.iso` | the bootable image — BIOS and UEFI, through Limine |
| `target/x86_64-unknown-none/release/bhaskix` | the kernel |
| `build/initrd.tar` | the initial files: every service and the shell |
| `boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi` | Bhaskix's own UEFI loader |

## Boot what you built

```sh
make demo
```

boots the machine the tests run against — two disks, a network, an IOMMU, a USB
keyboard — and hands you its shell:

```
Bhaskix -- a capability operating system, booting in QEMU

  This is the same machine the gates run against: two disks, a network,
  an IOMMU containing them, and a USB keyboard. …
…
  Bring-up complete. Nothing left to do at this milestone.

  a user-mode shell. 'help' lists what it can do.
bhaskix$
```

`Ctrl-A` then `x` leaves. `make run` boots a bare machine instead: one
read-only disk and no network, faster and able to do much less. `make run-uefi`
is the same under UEFI firmware.

**Use `make`, not `cargo build`, inside the tree.** Each program has its own link
script, and `make` passes it; a `cargo build` run by hand in a program's directory
produces a binary without it, and `make` then thinks there is nothing to do.
`cargo check` is always safe.

## Run the tests

```sh
make test
```

runs everything CI runs: formatting, lints, the host tests, the project's
invariant gates, and every boot lane — each boot checks hundreds of lines of the
machine's own report. It is serial on purpose and takes a while: from empty
build caches, 36 minutes on the machine these pages were checked on, counting
2,542 passing checks and 1,452 host tests. It ends:

```
…
  all checks passed
```

`make gates` runs only the fast checks — the invariants, in seconds — and is the
one to run before every commit. It is not the whole suite: it skips formatting,
lints and the boot lanes.

## Where to go next

- [Write a program](write-a-program.md) changes the demonstration program and
  runs it.
- [Run it on a real machine](real-hardware.md) puts what you built on a USB
  stick.
- `CONTRIBUTING.md` in the tree says how changes are proposed and reviewed.
