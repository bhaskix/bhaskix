<!-- SPDX-License-Identifier: Apache-2.0 -->

# Bhaskix — first release

**Status: DRAFT.** Written 2026-08-30 for the release dated **29 November 2026**
([roadmap.md](roadmap.md#first-release--29-november-2026), criterion R7). Every
number below is a measurement, and every measurement has a date. **They must be
re-taken on the day** — a release note that ships three-month-old figures is
making claims it has not checked.

---

## What this is

A **developer preview**: an ISO you can boot in QEMU, the source, the RFC
record, and this list of what does not work.

It is not a product, not an installer for a machine you rely on, and not a claim
of production readiness. The word for it is *preview*, and this document uses
that word deliberately rather than as modesty.

**Bhaskix is a capability-based operating system written in Rust.** There is no
`root` and no ambient authority: a program can do exactly what it holds a
capability for. Containers and virtual machines are not two mechanisms here —
they are the same primitive, a *domain*.

Original author and project lead: **Tarun Kumar Kushwaha**. Apache-2.0.

---

## What it does, and what proves it

Nothing is listed here that a gate does not prove. That rule is
[roadmap.md](roadmap.md)'s, not this document's: *"Until a gate proves a row, no
document, release note or README may state or imply that it works."*

| It does this | Proven by |
|---|---|
| Boots on BIOS, on UEFI, and on its own loader `bhaskixboot.efi` | the boot lanes; **119 gates** on the BIOS lane alone (measured 2026-08-30) |
| Starts four CPUs with its own INIT-SIPI and schedules across them | boot lanes, `threads`/`migration` gates |
| Runs ring 3 programs holding capabilities and nothing else | boot lanes, `ring 3` and fault-injection gates |
| Answers a user-mode shell from services in separate domains — block driver, console, filesystem | `shell-test.sh`; **22 gates** (`user` mode), **53** (`iommu` mode) |
| Keeps a journalled writable filesystem with a page cache **outside** the nucleus | `disk` shell mode |
| Speaks IPv4 and IPv6, UDP and TCP, both directions | RFC 0018, 0020, 0022, 0023, 0029 — each step measured before acceptance |
| Installs, runs and removes packages with manifest-derived grants | RFC 0030 |
| Programs an IOMMU and confines device DMA | `iommu` lanes; four units programmed on real hardware, 2026-08-25 |
| Loads and runs a real static Linux binary; BusyBox `sh` reaches a prompt and answers what is typed at it | `busybox-test.sh` |
| **Boots on physical hardware** — a Lenovo SR550, read over serial-over-LAN | 2026-08-23 |

Alongside: **1092 host unit tests**, and **42 of 59 RFCs accepted**, each
accepted one implemented and measured rather than merely written.

---

## What it does not do

Stated as plainly as the list above, because that is what criterion R7 asks for.

- **No libc, and no self-hosting.** Bhaskix cannot build itself.
- **The kernel is not authenticated by the loader.** This is
  [security.md](security.md) §1's top-ranked gap, deferred deliberately: it
  needs a TPM driver, a handoff change, and a key-custody decision this project
  has not made. A preview a stranger boots in QEMU is where that omission costs
  least, which is an argument for shipping it *said out loud*, not for leaving
  it unsaid.
- **No package repository, no signatures, no ABI stability.** Nothing here is
  promised to keep working across versions.
- **No desktop, no graphical environment.**
- **Networking has never run on physical hardware.** It needs a virtio NIC *and*
  an IOMMU; the one machine available has neither. Every networking number in
  this project is an emulator number, and none of them is a hardware claim.
- **No L1–L4 Linux application milestone is in this release.** The Linux
  personality ships as far as it has got — described by what it runs, not by
  what it is aimed at.

---

## Known defects, with their rates

These are open, reproducible, and recorded in [TRACKER.md](../TRACKER.md)'s
open-defects table with their specimens. They are listed here rather than left
for a user to discover.

| Defect | Rate |
|---|---|
| A ring station in a scheduler self-test sleeps through its own turn, halting that test | ~1 boot in 1200 |
| A kernel fault: control transfers to an unmapped address, alongside a trap frame whose vector field is garbage | ~1 boot in 2400 |
| Lock accounting occasionally disagrees with the guards it describes (a rank claimed with no open guard) | 3 sightings |
| A socket reclaim returns the slot but not the port, so an immediate re-bind is refused | 1 sighting only; 36 consecutive passes since |
| The RFC 0057 two-source park gate fails | ~2 in 1200 |
| CI's `interactive shell` job fails intermittently | ~7% of pushes |

**None of these has a fix.** Two fixes were made near the first while chasing
it — both closed real holes, and the write-up says plainly that neither was the
cause and that the rate did not move.

---

## What the one piece of hardware told us

The SR550 is the only physical machine this has run on, and it is worth being
precise about what that boot did and did not establish.

**It did:** boot, print its report over serial-over-LAN, start four CPUs, and
(since 2026-08-25) program all four IOMMU units, with `bin/ahcid` driving its
SATA controller.

**It did not:** find a disk — the machine's disks sit behind a RAID-mode
controller this driver refuses by name rather than guessing at. Its xHCI port 1
will not answer `SET_ADDRESS`. And it cannot test networking at all.

One machine is one machine. Nothing here should be read as "runs on servers".

---

## Review status

[roadmap.md](roadmap.md) criterion **R6** asks for the design documents to be
reviewed by two people who did not write them. **As of 2026-08-30 that is
unmet**, and it is Phase 0's own exit criterion, unmet since Phase 0.

If it is still unmet on 29 November, the release ships and says so. A preview
reviewed by one person is a truthful thing to publish and a dishonest thing to
dress up.

---

## Running it

```sh
tools/setup-dev.sh   # rust toolchain, qemu, limine, xorriso, ovmf
make                 # build the kernel and a bootable ISO
make demo            # the full machine: disks, network, IOMMU, USB keyboard
make run             # a bare machine, BIOS — faster, and does much less
make run-uefi        # the same under OVMF
make test            # everything CI runs
```

Builds on **stable Rust** — no nightly and no `#![feature]` anywhere in the
tree. Verified with Rust 1.97.1, QEMU 4.2.1 and Limine 8.7.0.

---

## Where the evidence is

- [TRACKER.md](../TRACKER.md) — what is *proven* versus what merely compiles,
  the open defects, and a changelog that records the mistakes as well as the
  results.
- [docs/rfc/](rfc/) — 59 RFCs; the 42 accepted ones were each built and measured
  before acceptance.
- [docs/security.md](security.md) — the threat model, and which threats are
  mitigated versus merely named.
- [docs/roadmap.md](roadmap.md) — scope, and the release criteria this note is
  written against.

If a document and the code disagree, that is a bug in one of them. Report it.
