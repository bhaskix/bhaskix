<!-- SPDX-License-Identifier: Apache-2.0 -->

# Bhaskix — first release

**Status: DRAFT.** Written 2026-08-30 for the release dated **29 November 2026**
([roadmap.md](roadmap.md#first-release--29-november-2026), criterion R7),
**refreshed 2026-10-08 and again 2026-10-19**. The release is tagged
**`v0.1.0-preview`**, and how it gets out the door is
[release-checklist.md](release-checklist.md). Every number below is a
measurement, and every measurement has a date. **They must be re-taken on the
day** — a release note that ships two-month-old figures is making claims it has
not checked.

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

> **What the 2026-10-19 refresh found.** Eleven days later, the note was wrong
> again, in both directions:
> - **It said "CI runs no native-loader lane"**, which had been false since
>   2026-10-11, when CI gained four.
> - **It said RFC 0089 was a draft and that nothing verified the TPM's
>   measurements.** The RFC was accepted 2026-10-11, and the event log has
>   been replayed against the PCRs on every TPM boot since — on the SR550 too.
> - **It listed `/proc/self` on the SR550 as an open defect**, fixed 2026-10-12.
> - **Its RFC count used a command that now overcounts by one**, because RFC
>   0092's status line says "connections nobody accepted". The count below is
>   anchored on the status cell instead.
> - **It did not mention a hosted program dialling out** (RFC 0090, accepted
>   2026-10-16), loopback, or the limits that work found.
>
> Its defects table was re-derived row by row from [TRACKER.md](../TRACKER.md)
> §3 on 2026-10-19, and the figures were re-measured from that day's full
> `make test`.

---

## What this is

A **developer preview**: an ISO you can boot in QEMU, the source, the RFC
record, and this list of what does not work. Beside the ISO the release carries
**`bhaskixboot.efi`**, Bhaskix's own UEFI loader, and a `SHA256SUMS` file. All
three are built by CI from the tagged commit.

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
| Boots on BIOS, on UEFI, and on its own loader `bhaskixboot.efi` | the boot lanes; **173 passing checks** on the BIOS lane alone (`ok` lines, measured 2026-10-19; 162 on 2026-10-08, 119 on 2026-08-30). ~~**CI runs no native-loader lane**; locally it runs three.~~ **Wrong since 2026-10-11, corrected 2026-10-19**: CI runs four native-loader lanes, two of them with an emulated TPM. On the one physical machine, **it boots through its own loader to the user-mode shell** — sixteen CPUs, observed 2026-10-11 (see [the hardware](#what-the-one-piece-of-hardware-told-us)) |
| Starts its CPUs with its own INIT-SIPI and schedules across them | boot lanes, `threads`/`migration` gates — four CPUs in the lanes, eight in the soaks, and **16 of 16** on the SR550 |
| Runs ring 3 programs holding capabilities and nothing else | boot lanes, `ring 3` and fault-injection gates |
| Answers a user-mode shell from services in separate domains — block driver, console, filesystem | `shell-test.sh`; **23 gates** (`user` mode), **54** (`iommu` mode), measured 2026-10-19 (22 and 53 on 2026-08-30) |
| Keeps a journalled writable filesystem with a page cache **outside** the nucleus | `disk` shell mode |
| Speaks IPv4 and IPv6, UDP and TCP, both directions | RFC 0018, 0020, 0022, 0023, 0029 — each step measured before acceptance |
| **Keeps loopback inside the host.** A hosted program sends itself a UDP datagram over `127.0.0.1` (2026-10-16), and dials its own TCP listener there (2026-10-19). A frame from a wire naming a loopback address is dropped, for either family | the `iommu` lane's loopback gates. The wire-side refusal is proven **on the host only**: no emulator lane can put such a frame on a wire |
| **A hosted program dials out, if it was granted to.** `connect` over TCP: 64 dials in a row, more than the pool holds; one not granted is refused with `EACCES`, and a refused dial reads `ECONNREFUSED`. The unmodified Go server dials with Go's own `net.Dial` | the gates of RFC 0090, accepted 2026-10-16, and two `httpd dial` gates in `make test-http`, which CI runs |
| Installs, runs and removes packages with manifest-derived grants | RFC 0030 |
| Programs an IOMMU and confines device DMA | `iommu` lanes; four units programmed on real hardware, 2026-08-25 |
| Loads and runs real static Linux binaries; BusyBox `sh` reaches a prompt and answers what is typed at it | `busybox-test.sh`, locally (CI does not run it — see [Running it](#running-it)). **This release's ISO does not carry BusyBox**: it is GPL-2.0, and shipping its binary would oblige publishing its source. A build from source picks it up from the build machine |
| **Runs an unmodified Go `net/http` server** as a hosted Linux process: 16 keep-alive clients for 300 s, **61,447 responses, every body checked, 0 errors** (2026-10-01); for 30 s on every push, **5,717 responses, 0 errors** (2026-10-19) | `make test-http` (30 s) in `make test` and CI; RFC 0086, accepted 2026-10-04. **This release's ISO carries the server** |
| Hosted Linux processes `fork` (a copy the kernel makes), wait on futexes, send, take and catch signals, are ended while running, and write and truncate files on disk | the gates of RFC 0079, 0080, 0083, 0084 and 0085, and of RFC 0060, 0065 and 0077 — all accepted |
| **Records what it booted in a TPM, and checks the record.** The native loader measures the kernel and initrd into PCR 9 and the command line into PCR 8. The event log reaches the kernel, and `bin/tpmd` **replays it against the TPM**: `log and TPM agree on PCRs 0-9` (2026-10-19), and a log that lies about the kernel is caught | `make test-boot-native-tpm` and `-tpm-tis`, against an emulated TPM (swtpm) over CRB and TIS. ~~**locally only** — it needs Docker, and CI does not run it yet. RFC 0089 is a **draft**, and nothing *verifies* the measurements~~ — **wrong since 2026-10-11, corrected 2026-10-19**: CI runs both lanes, and RFC 0089 was accepted 2026-10-11. On the SR550's own TPM: `log and TPM agree on PCRs 0-7, 9 ... over FIFO` (2026-10-11). **Recorded, not refused**: see below |
| **Boots on physical hardware** — a Lenovo SR550, read over serial-over-LAN | 2026-08-23 through Limine; through its own loader to the user-mode shell since 2026-10-11 |

Alongside, **as measured on 2026-10-19**: **61 of 92 RFCs accepted**, each
accepted one implemented and measured rather than merely written. The command:

```sh
for f in docs/rfc/0*.md; do grep -m1 Status "$f"; done \
  | grep -ciE '^\| \*\*Status\*\* \| *(✅ *)?\*\*accepted'
```

`docs/rfc/` holds 94 files: the template, `0040-libcrux-inspection.md` (RFC
0040's step-1 output rather than an RFC), and 92 RFCs. ~~`grep -ci accepted`~~
was this note's command until 2026-10-19, and it reads 62 from that day, because
RFC 0092's status says "connections nobody accepted". Host unit tests:
**1,398** (`cargo test --workspace`, summed across one `make test` run,
2026-10-19; 1,339 on 2026-10-08).

> **Dated 2026-09-23, because this line was the only measurement in the document
> without a date on it** — every row of the table above carries one. The header
> says these figures must be re-taken on the day and will go stale before then;
> a reader cannot act on that warning for a number that does not say when it was
> taken. Re-measured the same day, the RFC figure read **52 accepted of 85
> written**. ~~The test count is left for the day rather than half-refreshed
> here~~ — both were re-measured 2026-10-08 and 2026-10-19, above.

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
  [security.md](security.md) §1's top-ranked gap. The boot is **measured**,
  and since 2026-10-11 the measurements are **checked** — the log is replayed
  against the TPM, and a log that lies is caught (above). ~~nothing yet replays
  the log against the PCRs~~ was this line's wording until 2026-10-19. But
  checking a record is not refusing a kernel: nothing stops a kernel whose
  digest is wrong from running. Signing is
  [RFC 0091](rfc/0091-a-boot-its-owner-signed.md), a draft of 2026-10-12 with
  nothing built, which sets key custody out as decisions for the project lead. A
  preview a stranger boots in QEMU is where that omission costs least, which is
  an argument for shipping it *said out loud*, not for leaving it unsaid.
- **This release's binaries are not signed either.** `SHA256SUMS` sits beside
  them and detects a damaged download. It does not detect a malicious one,
  because anyone who could replace a binary could replace the sums.
- **Nothing written survives a reboot.** The writable filesystem is formatted
  at every boot: a package installed on one boot is gone on the next. Measured
  2026-10-19 — two boots on one disk image, `1 installed` and then `0 installed`.
  The format also writes over the marker the next boot's self-test reads, so a
  disk image must be remade for each boot, or that boot reports
  `block service FAILED`; [the guides](guide/README.md) say how.
- **No package repository, no signatures, no ABI stability.** Nothing here is
  promised to keep working across versions.
- **No desktop, no graphical environment.**
- **A hosted program cannot dial over IPv6.** Every hosted IPv6 dial is answered
  `ENETUNREACH` (filed 2026-10-16). IPv6 TCP, `::1` included, works only for
  Bhaskix's own programs.
- **A hosted listener cannot be closed.** Its port, its table slot and its
  buffers stay held for the rest of the boot. A server that closes and listens
  again is refused, and the adapter holds three listeners per boot.
  [RFC 0092](rfc/0092-a-listener-that-can-be-closed.md), drafted 2026-10-19
  with the lead's decisions, is the fix. Its step 0 measured the refusal:
  `listen -23`.
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
for a user to discover. ~~**Counted 2026-10-08: twenty rows not closed**~~ —
that count was right for its day. **Read row by row on 2026-10-19: twenty-three
rows not closed**, and twenty-four that evening. Booting an image built as the release will be, and typing at
its shell, found five more defects later that day; all five were fixed the same
day, and they are in the closed table. It also found the reboot limit above, the
twenty-fourth row. The table below groups two that are one family, and leaves
out one that is open in name only: the `uefi, qemu64` lane, restored to
`make test` and failing only by other rows' defects. Eleven rows closed between
the two refreshes, and with the five found and fixed later the same day they are
in the second table.

| Defect — what you would see | Rate, as TRACKER states it | Fix |
|---|---|---|
| An outbound TCP demonstration stalls: `connected, stream still in flight` | 11 sightings in 7,762 boots, 1 in 705, counted by the tool; the latest specimens 2026-09-29 (CI run 782) and 2026-10-02 | none |
| The four-client TCP act accepts nobody: `tcp four FAILED ... 0 accepted` | **3 sightings** (2026-10-12, twice on 2026-10-15). A fourth was counted, and dated 2026-10-16; it ran on 2026-10-19, was the test harness's own fault, and is withdrawn | not explained |
| The inbound TCP echo is served and the host never receives the bytes | **4 sightings** (CI 2026-09-13, 09-23, 10-08; locally 10-15) | the host's driver changed 2026-10-19 to stay and hear its reply; open until it has gone a while without a sighting |
| A hosted UDP read never ends (the probe thread spins) | 5 times locally, the last 2026-10-10; 0 in 8,065 CI boots | none |
| A ring-station scheduler self-test halts with a station asleep on its own turn | 20 in 7,891 boots before a fix of 2026-09-28; **0 in 657 since** (2026-10-04) | fix landed; open until ~1,200 clean boots |
| A lock-order self-test fails: a wait queue taken while holding another lock | 4 in 7,681 boots; last 2026-09-23 | a cause fixed 2026-09-28; open until ~5,800 clean boots |
| The lock-order detector fires in CI: one real ordering violation | 1 sighting, CI run 489 (2026-09-02); again 2026-09-04 | not explained |
| Lock accounting disagrees with the locks actually held (`no open guard`) | four specimens, the last 1 boot in 24 at eight CPUs (2026-09-04); two were withdrawn as instrument errors | one specimen unexplained |
| The two-wake-sources self-test (RFC 0057) fails | ~2 boots in 1,200; last 2026-09-04 | none |
| CI's `interactive shell` job goes red | ~1 in 21 runs after a split; mostly other rows' defects surfacing there | none of its own |
| The TCP self-test reports a connection served without a verified SYN cookie | 4 sightings; 0 in 6,427 CI boots (2026-09-14); 0 in 24 at eight CPUs (2026-10-02) | not claimed fixed; the old reproducer no longer reproduces |
| A freshly created domain refuses the Linux personality | 1 sighting each in two forms (2026-09-02, 2026-09-13); 0 in 6,427 CI boots | both known windows shut; open |
| A Linux memory self-test sees `mmap` return 0 or 1 | **3 specimens** (2026-09-02 twice, 2026-10-09) | ~~likely fixed, not proven~~ — the third specimen refuted the fix (2026-10-09); a detector was built 2026-10-10 and has not yet fired |
| The hosted TCP server demonstration quits without answering | 1 sighting (2026-09-30) | mitigated, not closed |
| The BusyBox test's keyboard is never handed over, and `sh` shows no prompt | 1 local suite (2026-09-30); not in CI | none |
| A boot stops printing partway through a test | 1 sighting, CI run 792 (2026-09-30) | unexplained, not yet instrumented |
| A `poll` probe says "not ready" for a domain with no console grant | 1 sighting (2026-10-12) | parked until the next one; the cause is an inference |
| The native TPM lane's second serial log comes back empty | 1 in 9 runs (2026-10-11) | instrumented, not explained |
| The LACP test's report ends with no state line | 1 sighting (2026-10-16) | not explained |
| A second boot on the same disk image reports `block service FAILED` | every such boot (2026-10-19) | not fixed: the boot's format writes over the marker its self-test reads. Remake the image before each boot, as the guides say |
| BusyBox `sh` faults at `0x48` | ~2% of harness runs; 0 of 8,443 CI boots (2026-10-04) | likely fixed 2026-10-02, not proven |
| A per-CPU hold count underflows (the remainder of the old "445 ms wake" row) | no specimen in 450 boots of one image (2026-08-28) | a cause guarded 2026-09-03; not shown to be *the* cause |

**Several of these have fixes waiting on a count**, and the column says which.
"Likely fixed, not proven" means exactly that: a clean run at the old rate is
not yet absence.

**Closed since the first draft, and kept here so the record shows it:**

| Defect | Closed |
|---|---|
| The shell's `pkg` messages printed `?[1;32minstalled?[0m`: it colours its output, and the console turned every escape from a ring-3 program into `?` | **2026-10-19**, by the lead's decision — colour passes, and nothing else does: clearing, cursor movement, blink, conceal and reverse are still refused, and a coloured line ends with a reset ([RFC 0052](rfc/0052-a-line-that-waits-for-its-newline.md), amended) |
| A package's output and the shell's interleaved on the console, in sixteen-byte pieces | **2026-10-19**, found typing `pkg run hello` — the four line holders were given back only on a read, so writers that never read kept them; a finished line now gives its holder back, and a host test reproduces the boot's specimen against the old rule byte for byte |
| `held`, typed after an `open` that failed or after a `release`, ended the user-mode shell: it read an unmapped page, and a fault ends the domain | **2026-10-19**, found typing the shell's own commands as a newcomer would — `held` now says nothing is lent, and the shell test types it after `release` |
| With an IOMMU and only the boot CD on the SATA controller, the AHCI self-test reported `FAILED` twice, counting the CD as a disk | **2026-10-19**, found booting the release's ISO with a network — the count follows the driver's own decision, host-tested |
| The native loader refused the release's own initrd, 6,993,920 bytes against a 4 MiB buffer, with a bare status | **2026-10-19** — sixteen MiB, the kernel's figure, and an oversized payload refused in words |
| Through its own loader on the SR550, a hosted program reading `/proc/self` never finished (five of five sixteen-CPU boots) | **2026-10-12** — the cause was the console, not the program: every line waited on a framebuffer scroll that read video memory back. With the text kept in RAM, the machine reached its services in 98 s instead of 589 s, and in 79 s once the framebuffer was mapped write-combining. `linux proc` passes there. This note listed it as open until 2026-10-19 |
| A forked or exec'd child in a recycled slot was ended by its predecessor's cleanup | **2026-10-16** — the adapter's handle is installed when the domain is made |
| A wire frame addressed to `::1` would have been delivered | **2026-10-16** — one verdict per family on what comes off a wire; found by reading, proven on the host only |
| Probe self-tests read their answers before the probe had finished | **2026-10-15** — every probe goes through one helper that waits for its last word |
| The `iommu` lane's refused boot overran its 120 s | **2026-10-19** — the harness stops that boot at its own last line |
| On CI's emulator, the native lane hung on a page fault at 768 GiB | **2026-10-11** — every kernel-half slot is built at boot |
| The loader appended the TPM's final events twice | **2026-10-11** — it appends only what follows its own read of the log; confirmed on the SR550 |
| A TIS TPM was reported as "no TPM2 table" | **2026-10-11** |
| The SR550's firmware hashes a zero-length buffer wrongly | **2026-10-11, worked around, not fixed** — an empty command line is not measured; the firmware is unchanged |
| A kernel fault: control transfers to an unmapped address beside a trap frame with a garbage vector (~1 boot in 2400) | **2026-10-07** — a thread stolen while its CPU still ran it; fixed 2026-10-04, 0 faults in 1,230 passes at eight CPUs since |
| A socket reclaim returned the slot but not the port | **2026-09-02** — the gate raced its own precondition. ~~2026-09-01~~ was this table's date until 2026-10-19: that closure was reopened the same day and closed again on the 2nd |
| The TCP inbound gate failed at an environmental rate | **2026-08-31** — [RFC 0061](rfc/0061-a-connection-nobody-accepted.md): a connection nobody accepted held the only slot |
| SMEP and SMAP were enabled on one CPU of four (one of sixteen on the SR550), and under the native loader write protection on none the kernel started — while the report said "on" | **2026-10-08** — every CPU now enables and reads back all three, gated on every lane |
| Through its own loader, the SR550 ended every boot with no console input: the serial line read back masked | **2026-10-11** — the line was waiting for an acknowledge and the check misread it; the machine now takes that branch and goes on |
| Through its own loader, the SR550 started one CPU of sixteen | **2026-10-08** — bring-up tables from below 4 GiB; sixteen of sixteen on the machine |
| Through its own loader, a copy-on-write write on the SR550 landed in the original frame | **2026-10-08** — nothing set `CR0.WP`; set on every CPU, and the machine passes |
| The native loader stopped on the SR550 after leaving the firmware | **2026-10-08** — its page-table pool was sized under an emulator; sized from the machine, it boots there |
| Every boot showed a 442–447 ms worst wake | **2026-08-16** — one missing `resched()` on spawn; 446 ms → 345 µs. This note listed it as open two weeks later, which was wrong when written |

---

## What the one piece of hardware told us

The SR550 is the only physical machine this has run on, and it is worth being
precise about what that boot did and did not establish.

**It did:**
- boot through Limine, print its report over serial-over-LAN, and start all
  **16** of its CPUs;
- program all four IOMMU units (since 2026-08-25);
- drive its SATA controller with `bin/ahcid`;
- drive its Intel X722 network ports from ring 3, each confined by its own DMA
  window (since 2026-09-07), and answer a ping (2026-09-13);
- **boot through Bhaskix's own loader to the user-mode shell** (observed
  2026-10-11), with every self-test passing there since the console fix of
  2026-10-12;
- **replay its TPM's event log against the TPM** (2026-10-11).

**It did not:**

- **Find a disk.** Read from the machine's own service processor on 2026-10-08:
  every drive it has sits behind a ThinkSystem RAID 530-8i (a Broadcom SAS3408
  MegaRAID) — a different device from the SATA controller `bin/ahcid` drives,
  which has nothing attached. ~~Its disks sit behind a RAID-mode controller this
  driver refuses by name~~ was this section's wording until then, and named the
  wrong controller. The drives belong to the machine's other job and are not
  this project's to write.
- ~~**Boot fully through Bhaskix's own loader** — until 2026-10-08, and now with
  three gaps.~~ **It does now** — see the list above; this bullet was moved there
  on 2026-10-19. The history, kept: `bhaskixboot.efi` printed its banner there
  and nothing after on four boots of 2026-08-22, because it wrote everything else
  to the first UART and this machine's service processor carries the second.
  Writing both, a boot on 2026-10-08 heard it refuse after leaving the firmware:
  its page-table pool was sized under an emulator with 256 MiB, and this machine
  has 192 GiB. Sized from the machine, a second boot the same day reached the
  kernel and its whole report — with one CPU of sixteen and a failed
  copy-on-write check, both fixed the same day. ~~**On 2026-10-10 it reached the
  shell**~~ — corrected 2026-10-11: that was not observed; the boots were stopped
  at a shell *self-test's* banner. **Observed 2026-10-11 on a boot run to its end:
  the user-mode shell starts.** ~~a hosted program reading `/proc/self` has not
  finished on any of five boots through this loader~~ — fixed 2026-10-12 (the
  closed table above).
- **Get an answer to `SET_ADDRESS` from whatever is on its xHCI's port 1.**
- **Obtain an address, start an exchange, or carry TCP** on its network.

One machine is one machine. Nothing here should be read as "runs on servers".

---

## Review status

[roadmap.md](roadmap.md) criterion **R6** asks for the design documents to be
reviewed by two people who did not write them. **As of 2026-10-19 that is
unmet**, and it is Phase 0's own exit criterion, unmet since Phase 0. The
review packet is [review-guide.md](review-guide.md), about 3½ hours of reading.

If it is still unmet on 29 November, the release ships and says so. A preview
reviewed by one person is a truthful thing to publish and a dishonest thing to
dress up.

---

## Running it

**From the release.** Download `bhaskix.iso`, `bhaskixboot.efi` and
`SHA256SUMS` from the `v0.1.0-preview` release on GitHub, then check them:

```sh
sha256sum -c SHA256SUMS
```

Boot the ISO under BIOS, then under UEFI. Both reach the user-mode shell,
`bhaskix$`; leave QEMU with `Ctrl-A x`.

```sh
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -cdrom bhaskix.iso

cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -cdrom bhaskix.iso
```

Boot through Bhaskix's own loader. It reads the kernel and initrd from an EFI
system partition, here a directory QEMU serves as one. Both files come off the
ISO:

```sh
mkdir -p esp/EFI/BOOT esp/bhaskix
cp bhaskixboot.efi esp/EFI/BOOT/BOOTX64.EFI
xorriso -osirrox on -indev bhaskix.iso \
    -extract /boot/bhaskix esp/bhaskix/kernel \
    -extract /boot/initrd.tar esp/bhaskix/initrd.tar
cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -drive format=raw,file=fat:rw:esp
```

All three were run on 2026-10-19, from copies of that day's build, under QEMU
4.2.1, and typed at: `caps` answered, and `Ctrl-A x` ended QEMU. That needs
`mon:stdio` — with plain `-serial stdio`, `Ctrl-A x` does nothing. The first runs
left out `-smp 4`, and ~~two self-tests reported "skipped" for want of a second
and a third CPU~~ **thirty-two self-tests reported `skipped` for want of CPUs,
and one more for want of an IOMMU** — corrected the same day: the first count
read only the report's last lines. The lanes boot four CPUs, and there those
thirty-two run. The OVMF paths are
this host's, Ubuntu 20.04; a newer distribution may name the pair
`OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`, and the two must match. A line `cmdline=<options>` in
`esp/bhaskix/boot.conf` sets the kernel's command line; the ISO's command line
is fixed.

**Guides** — booting it, its shell and packages, and running a Linux program on
it, every command run and every output copied from the run — are in
[docs/guide/](guide/README.md).

**From source:**

```sh
tools/setup-dev.sh   # rust toolchain, qemu, limine, xorriso, ovmf
make                 # build the kernel and a bootable ISO
make demo            # the full machine: disks, network, IOMMU, USB keyboard
make run             # a bare machine, BIOS — faster, and does much less
make run-uefi        # the same under OVMF
make test            # everything CI runs, and the lanes it does not
```

`make test` runs more than CI does: the `iommu-off` and placement lanes, the
PS/2 and USB keyboard lanes, BusyBox, bonding and LACP. ~~the native-loader
lanes, and the TPM lane~~ were this paragraph's examples until 2026-10-19; CI
has run those since 2026-10-11. The TPM lanes need **Docker** for their emulated
TPM, and skip with a note without it. `tools/setup-dev.sh` does not install
Docker.

Builds on **stable Rust** — no nightly and no `#![feature]` anywhere in the
tree. Verified 2026-10-19 with Rust 1.98.0 (pinned in `rust-toolchain.toml`),
QEMU 4.2.1 here and 8.2.2 in CI, and Limine 8.7.0 (`v8.7.0-binary`).
`setup-dev.sh` follows Limine's `v8.x-binary` branch rather than a tag, so a
fresh checkout may build against a later 8.x; the release build pins the tag.

---

## Where the evidence is

- [TRACKER.md](../TRACKER.md) — what is *proven* versus what merely compiles,
  the open defects, and a changelog that records the mistakes as well as the
  results.
- [docs/rfc/](rfc/) — 92 RFCs; the 61 accepted ones were each built and measured
  before acceptance (2026-10-19).
- [docs/security.md](security.md) — the threat model, and which threats are
  mitigated versus merely named.
- [docs/roadmap.md](roadmap.md) — scope, and the release criteria this note is
  written against.
- [release-checklist.md](release-checklist.md) — how this release is built,
  checked and published.

If a document and the code disagree, that is a bug in one of them. Report it.
