<!-- SPDX-License-Identifier: Apache-2.0 -->

# Bhaskix — first release

**Status: DRAFT.** Written 2026-08-30 for the release dated **29 November 2026**
([roadmap.md](roadmap.md#first-release--29-november-2026), criterion R7), and
**refreshed 2026-10-08**. Every number below is a measurement, and every
measurement has a date. **They must be re-taken on the day** — a release note
that ships two-month-old figures is making claims it has not checked.

**That is not a formality.** The test count in this document went stale within
*hours* of being written, because four tests were added the same afternoon. Some
of these figures change with almost every commit, and gating them would force an
edit to this file each time a test is added — which trades a stale number for a
worse habit. So they are dated instead, and re-measuring them is the last step
before release, not an optional one. The commands are in [Running it](#running-it);
the counts come from `make test` and `cargo test --workspace`.

> **What the 2026-10-08 refresh found.** Five weeks after it was written, this
> note was wrong in ways a reader would have acted on, and they are listed so
> the next refresh knows what to look for. It said networking had never run on
> physical hardware — false since 2026-09-13. Its known-defects table listed
> eight rows: one was closed (the kernel fault, 2026-10-07), two had been
> resolved within days of the note being written (the socket reclaim on
> 2026-09-01 and the TCP inbound gate on 2026-08-31), one described a
> signature fixed two weeks *before* it was written (the every-boot 445 ms
> wake, 2026-08-16) — and it said "none of these has a fix". Meanwhile twelve
> defects filed since were not in it at all. And it did not mention the
> largest thing the system had done since: a Go web server. Every row below
> was re-checked against [TRACKER.md](../TRACKER.md) on 2026-10-08.

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
| Boots on BIOS, on UEFI, and on its own loader `bhaskixboot.efi` | the boot lanes; **162 passing checks** on the BIOS lane alone (`ok` lines, measured 2026-10-08; 119 on 2026-08-30). **CI runs no native-loader lane**; locally it runs three. On the one physical machine it **completed a boot on 2026-10-08**, with one CPU of sixteen and no shell (see [the hardware](#what-the-one-piece-of-hardware-told-us)) |
| Starts its CPUs with its own INIT-SIPI and schedules across them | boot lanes, `threads`/`migration` gates — four CPUs in the lanes, eight in the soaks, and **16 of 16** on the SR550 |
| Runs ring 3 programs holding capabilities and nothing else | boot lanes, `ring 3` and fault-injection gates |
| Answers a user-mode shell from services in separate domains — block driver, console, filesystem | `shell-test.sh`; **22 gates** (`user` mode), **53** (`iommu` mode), measured 2026-08-30 and not re-counted since |
| Keeps a journalled writable filesystem with a page cache **outside** the nucleus | `disk` shell mode |
| Speaks IPv4 and IPv6, UDP and TCP, both directions | RFC 0018, 0020, 0022, 0023, 0029 — each step measured before acceptance |
| Installs, runs and removes packages with manifest-derived grants | RFC 0030 |
| Programs an IOMMU and confines device DMA | `iommu` lanes; four units programmed on real hardware, 2026-08-25 |
| Loads and runs real static Linux binaries; BusyBox `sh` reaches a prompt and answers what is typed at it | `busybox-test.sh` |
| **Runs an unmodified Go `net/http` server** as a hosted Linux process: 16 keep-alive clients for 300 s, **61,447 responses, every body checked, 0 errors** (2026-10-01) | `make test-http` (30 s) in `make test` and CI; RFC 0086, accepted 2026-10-04 |
| Hosted Linux processes `fork` (a copy the kernel makes), wait on futexes, send, take and catch signals, are ended while running, and write and truncate files on disk | the gates of RFC 0079, 0080, 0083, 0084 and 0085, and of RFC 0060, 0065 and 0077 — all accepted |
| **Records what it booted in a TPM**: the native loader measures the kernel and initrd into PCR 9 and the command line into PCR 8, the event log reaches the kernel, and `bin/tpmd` reads the PCRs back — a changed kernel byte moves PCR 9 and nothing else | `make test-boot-native-tpm`, **against an emulated TPM (swtpm) only, locally only** — it needs Docker, and CI does not run it yet. RFC 0089 is a **draft**, and nothing *verifies* the measurements: see below |
| **Boots on physical hardware** — a Lenovo SR550, read over serial-over-LAN | 2026-08-23 |

Alongside, **as measured on 2026-10-08**: **59 of 89 RFCs accepted**, each
accepted one implemented and measured rather than merely written (`for f in
docs/rfc/0*.md; do grep -m1 Status "$f"; done | grep -ci accepted`, excluding
the template; 90 files, one of which — `0040-libcrux-inspection.md` — is RFC
0040's step-1 output rather than an RFC). Host unit tests: **1,339** (`cargo test --workspace`, summed across one `make test` run).

> **Dated 2026-09-23, because this line was the only measurement in the document
> without a date on it** — every row of the table above carries one. The header
> says these figures must be re-taken on the day and will go stale before then;
> a reader cannot act on that warning for a number that does not say when it was
> taken. Re-measured the same day, the RFC figure read **52 accepted of 85
> written**. ~~The test count is left for the day rather than half-refreshed
> here~~ — both were re-measured 2026-10-08, above.

---

## What it does not do

Stated as plainly as the list above, because that is what criterion R7 asks for.

- **No self-hosting.** Bhaskix cannot build itself. It moved to milestone L2 on
  2026-10-07, when Phase 2 closed without it.
- **No native libc, by design.** [RFC 0005](rfc/0005-linux-abi-compatibility.md), accepted
  as amended 2026-10-07: a native program speaks the capability interface
  directly, and a Linux program brings its own libc and runs through the Linux
  personality. ~~No libc~~ was this line's wording until 2026-10-08, which read
  as a gap still to close rather than a decision.
- **The kernel is not authenticated by the loader.** This is
  [security.md](security.md) §1's top-ranked gap. Since 2026-10-08 the boot is
  **measured** — a TPM records what the loader loaded (above) — but measuring
  is not verifying: nothing yet replays the log against the PCRs, nothing
  refuses a kernel whose digest is wrong, and signing waits on a key-custody
  decision this project has not made. A preview a stranger boots in QEMU is
  where that omission costs least, which is an argument for shipping it *said
  out loud*, not for leaving it unsaid.
- **No package repository, no signatures, no ABI stability.** Nothing here is
  promised to keep working across versions.
- **No desktop, no graphical environment.**
- **Networking on physical hardware is narrow.** ~~Networking has never run on
  physical hardware~~ — **wrong since 2026-09-13**, and this line said it until
  2026-10-08: a host on the SR550's network pinged it and **it replied**, through
  its own Intel X722 driver running in ring 3, and again on a four-port
  bond. That is ARP and ICMP *answered*. Not yet shown on hardware: a
  DHCP lease, an exchange this machine starts, or TCP. Every other networking
  number in this project is an emulator number. The X722 and bonding RFCs
  (0072–0076) are drafts.
- **No L1–L4 Linux application milestone is in this release.** The Linux
  personality ships as far as it has got — described by what it runs, not by
  what it is aimed at.

---

## Known defects, with their rates

These are open, reproducible, and recorded in [TRACKER.md](../TRACKER.md)'s
open-defects table with their specimens. They are listed here rather than left
for a user to discover. **Counted 2026-10-08: twenty open rows**, then twenty-two by the evening — the native loader's row closed when the SR550 booted through it, and that boot filed three; the table
groups the ones that are one family and leaves out one that is open in name
only (the `uefi, qemu64` lane, restored to `make test` and failing only by
other rows' defects).

| Defect — what you would see | Rate, as TRACKER states it | Fix |
|---|---|---|
| Through its own loader on the SR550, the kernel starts one CPU of sixteen: its bring-up tables land above 4 GiB | found 2026-10-08, every native boot of a machine with RAM above 4 GiB | **fixed 2026-10-08**, shown under KVM at 8 GiB; not yet confirmed on the SR550 |
| Through its own loader on the SR550, the serial line reads back masked, so there is no console input and no shell | found 2026-10-08, one boot | a lead, not a finding |
| Through its own loader on the SR550, a copy-on-write write lands in the original frame | found 2026-10-08, one boot | a lead: a stale TLB entry with one CPU online |
| A ring-station scheduler self-test halts with a station asleep on its own turn | 1 in 391 CI boots before a fix of 2026-09-28; **0 in 657 since** (2026-10-04) | fix landed; open until ~1,200 clean boots |
| An outbound TCP demonstration stalls: `connected, stream still in flight` | 10 sightings, 1 in 773 boots (2026-09-28) | none |
| A lock-order self-test fails: a wait queue taken while holding another lock | 4 in 7,681 boots; last 2026-09-23 | a cause fixed 2026-09-28; open until ~5,800 clean boots |
| Lock accounting disagrees with the locks actually held (`no open guard`) | four specimens, the last 1 boot in 24 at eight CPUs (2026-09-04); two were withdrawn as instrument errors | one specimen unexplained |
| The two-wake-sources self-test (RFC 0057) fails | ~2 boots in 1,200; last 2026-09-04 | none |
| CI's `interactive shell` job goes red | ~1 in 21 runs after a split; mostly other rows' defects surfacing there | none of its own |
| A hosted UDP read never ends (the probe thread spins) | 4 times locally, 0 in 8,065 CI boots (2026-10-01) | none |
| The inbound TCP echo is served and the host never receives the bytes | 2 sightings (2026-09-13, 2026-09-23) | none |
| The TCP self-test reports a connection served without a verified SYN cookie | 4 sightings; 0 in 6,427 CI boots (2026-09-14); 0 in 24 at eight CPUs (2026-10-02) | not claimed fixed; the old reproducer no longer reproduces |
| A freshly created domain refuses the Linux personality | 1 sighting each in two forms (2026-09-02, 2026-09-13); 0 in 6,427 CI boots | both known windows shut; open |
| The hosted TCP server demonstration quits without answering | 1 sighting (2026-09-30) | mitigated, not closed |
| The BusyBox test's keyboard is never handed over, and `sh` shows no prompt | 1 local suite (2026-09-30); not in CI | none |
| A boot stops printing partway through a test | 1 sighting, CI run 792 (2026-09-30) | unexplained, not yet instrumented |
| A Linux memory self-test sees `mmap` return 0 or 1 | 2 specimens (2026-09-02) | likely fixed, not proven |
| BusyBox `sh` faults at `0x48` | ~2% of harness runs; 0 of 8,443 CI boots (2026-10-04) | likely fixed 2026-10-02, not proven |
| A per-CPU hold count underflows (the remainder of the old "445 ms wake" row) | no specimen in 450 boots of one image (2026-08-28) | a cause guarded 2026-09-03; not shown to be *the* cause |

**Several of these have fixes waiting on a count**, and the column says which.
"Likely fixed, not proven" means exactly that: a clean run at the old rate is
not yet absence.

**Closed since the first draft, and kept here so the record shows it:**

| Defect | Closed |
|---|---|
| A kernel fault: control transfers to an unmapped address beside a trap frame with a garbage vector (~1 boot in 2400) | **2026-10-07** — a thread stolen while its CPU still ran it; fixed 2026-10-04, 0 faults in 1,230 passes at eight CPUs since |
| A socket reclaim returned the slot but not the port | **2026-09-01** — the gate raced its own precondition |
| The TCP inbound gate failed at an environmental rate | **2026-08-31** — [RFC 0061](rfc/0061-a-connection-nobody-accepted.md): a connection nobody accepted held the only slot |
| The native loader stopped on the SR550 after leaving the firmware | **2026-10-08** — its page-table pool was sized under an emulator; sized from the machine, it boots there |
| Every boot showed a 442–447 ms worst wake | **2026-08-16** — one missing `resched()` on spawn; 446 ms → 345 µs. This note listed it as open two weeks later, which was wrong when written |

---

## What the one piece of hardware told us

The SR550 is the only physical machine this has run on, and it is worth being
precise about what that boot did and did not establish.

**It did:** boot through Limine, print its report over serial-over-LAN, start
all **16** of its CPUs, program all four IOMMU units (since 2026-08-25), drive its
SATA controller with `bin/ahcid`, and — since 2026-09-07 — drive its Intel X722
network ports from ring 3, each confined by its own DMA window, and answer a
ping (2026-09-13).

**It did not:**

- **Find a disk.** Read from the machine's own service processor on 2026-10-08:
  every drive it has sits behind a ThinkSystem RAID 530-8i (a Broadcom SAS3408
  MegaRAID) — a different device from the SATA controller `bin/ahcid` drives,
  which has nothing attached. ~~Its disks sit behind a RAID-mode controller this
  driver refuses by name~~ was this section's wording until then, and named the
  wrong controller. The drives belong to the machine's other job and are not
  this project's to write.
- **Boot fully through Bhaskix's own loader** — until 2026-10-08, and now with
  three gaps. `bhaskixboot.efi` printed its banner there and nothing after on four
  boots of 2026-08-22, because it wrote everything else to the first UART and this
  machine's service processor carries the second. Writing both, a boot on
  2026-10-08 heard it refuse after leaving the firmware: its page-table pool was
  sized under an emulator with 256 MiB, and this machine has 192 GiB. Sized from
  the machine, **a second boot the same day reached the kernel and its whole
  report** — with **one CPU of sixteen** (the kernel's own CPU bring-up put its
  tables above 4 GiB), **no shell** (the serial line read back masked), and a
  failed copy-on-write check. Through Limine, the same machine runs all sixteen.
- **Get an answer to `SET_ADDRESS` from whatever is on its xHCI's port 1.**
- **Obtain an address, start an exchange, or carry TCP** on its network.

One machine is one machine. Nothing here should be read as "runs on servers".

---

## Review status

[roadmap.md](roadmap.md) criterion **R6** asks for the design documents to be
reviewed by two people who did not write them. **As of 2026-10-08 that is
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
make test            # everything CI runs, and the lanes it does not
```

`make test` runs more than CI does: the native-loader lanes, and the TPM lane,
which needs **Docker** for its emulated TPM and skips with a note without it.
`tools/setup-dev.sh` installs neither.

Builds on **stable Rust** — no nightly and no `#![feature]` anywhere in the
tree. Verified 2026-10-08 with Rust 1.98.0 (pinned in `rust-toolchain.toml`),
QEMU 4.2.1 here and 8.2.2 in CI, and Limine 8.7.0. `setup-dev.sh` follows
Limine's `v8.x-binary` branch rather than a tag, so a fresh checkout may build
against a later 8.x.

---

## Where the evidence is

- [TRACKER.md](../TRACKER.md) — what is *proven* versus what merely compiles,
  the open defects, and a changelog that records the mistakes as well as the
  results.
- [docs/rfc/](rfc/) — 89 RFCs; the 59 accepted ones were each built and measured
  before acceptance (2026-10-08).
- [docs/security.md](security.md) — the threat model, and which threats are
  mitigated versus merely named.
- [docs/roadmap.md](roadmap.md) — scope, and the release criteria this note is
  written against.

If a document and the code disagree, that is a bug in one of them. Report it.
