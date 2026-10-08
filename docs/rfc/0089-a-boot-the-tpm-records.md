# RFC 0089: A boot the TPM records

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-10-07 — steps 1 and 2 done the same day: this host's OVMF offers `EFI_TCG2_PROTOCOL` when a TPM is attached, and the native loader measures the kernel, initrd and command line through it**, gated in `make test-boot-native-tpm` from an emulator `tools/swtpm.sh` runs. The log does not reach the kernel yet (step 3). The first of Phase 3's secure boot chain, sequenced by the project lead on 2026-10-07: *measured boot first*, signing after key custody is decided. The acceptance call is the project lead's |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | boot (`bhaskixboot.efi`, `bhaskix_boot::Handoff`), arch (ACPI `TPM2`), kernel (boot report), userspace (a TPM service), tools, tests |
| **Milestone** | Phase 3 — *Secure boot chain*, the roadmap's first row; [security.md](../security.md) §1 **T6** and gap 1 |
| **Depends on** | [RFC 0028](0028-bhaskixboot.md) (the loader that measures), [RFC 0013](0013-service-framework.md) and [RFC 0014](0014-driver-framework.md) (the TPM service), [RFC 0030](0030-packages.md) (the tree's SHA-256, `pkg/src/sha256.rs`, which replays the log), [RFC 0012](0012-iommu.md) (no DMA: a TPM interface is MMIO only) |

---

## Summary

Today the kernel is loaded with no record of what was loaded: whoever can write the ESP replaces it,
and nothing afterwards can tell. This RFC makes the project's own UEFI loader **measure** what it
loads — the kernel image, the initrd and the command line — into TPM 2.0 PCRs through the firmware's
`EFI_TCG2_PROTOCOL`, carries the firmware's **event log** to the kernel through the boot handoff,
and adds a **TPM 2.0 service** that reads the PCRs back and replays the log with the tree's own
SHA-256, so the boot report can say whether the log and the TPM agree. It **enforces nothing**: a replaced kernel still boots, but it boots *recorded*,
in a register the replaced kernel cannot rewrite. Refusing to boot a kernel that is not ours is
signing, which needs the key-custody decision this RFC deliberately does not take.

## Motivation

[security.md](../security.md) §1 ranks *the kernel image has no authenticity check* as its first gap,
and T6 reads "UEFI Secure Boot chain; measured boot into TPM PCRs; signed, immutable system image —
⬜ planned, not built". The roadmap's Phase 3 row names three prerequisites — a TPM 2.0 driver, a
`HANDOFF_VERSION` bump, and key custody — and the third is a governance question
([GOVERNANCE.md](../../GOVERNANCE.md), security.md §10). RFC 0030 refused package signatures for the
same reason: *a signature without key storage, distribution or revocation is theatre*.

**Measurement needs none of the three's governance.** It is the half of the chain that produces
evidence rather than verdicts, and every later piece consumes it: sealing a key to a known boot,
remote attestation (T8, *partial*), and — once custody is decided — a verifier that knows which
digests a signed kernel should produce. Doing nothing leaves the first gap with no instrument at
all; doing this leaves it open but *observable*.

Two facts from the tree shape the design. **The measuring stage is only exercised on the native
lanes**, and CI runs none of them (`.github/workflows/ci.yml` has no native job). And **the native
loader does not complete a boot on the SR550** — it stops after its banner, 2026-08-22, still
unexplained — so hardware testing waits on that, and this RFC says so rather than assuming it.

## Design

### What is measured, where, and as what

The firmware measures `bhaskixboot.efi` itself into **PCR 4** before running it (the registry's
"boot loader and additional drivers"); the loader measures what it reads, **before** `ExitBootServices`, because the
protocol does not survive it:

| Object | PCR | Event type | Event data |
|---|---|---|---|
| kernel image, as read from `bhaskix\kernel` | 9 | `EV_EVENT_TAG` (0x6) | tag + `"bhaskix kernel"` |
| initrd, as read from `bhaskix\initrd.tar` | 9 | `EV_EVENT_TAG` | tag + `"bhaskix initrd"` |
| command line, after `cmdline=` is stripped | 8 | `EV_EVENT_TAG` | tag + `"bhaskix cmdline"` |

**PCRs 8 and 9 because the platform firmware profile gives the OS PCRs 8–15** and grub's practice is
8 for commands and the command line, 9 for files read — recorded in the UAPI group's Linux TPM PCR
Registry, which also lists 10–15 as taken by IMA, `systemd-stub`, shim and cryptsetup. Following an
existing convention keeps a verifier's tooling usable on this machine. **`EV_EVENT_TAG` is verified**
(`0x00000006`, EDK2's `UefiTcgPlatform.h`); grub's `EV_IPL` is defined in the PC Client profile, which
could not be read when this was drafted, so which of the two is right is unresolved question 1, not an
assertion. The kernel is ELF, so the `PE_COFF_IMAGE` flag (`0x10`) is **not** set: the firmware hashes
the bytes as given.

**The kernel is measured as read, not as placed.** Placement and the KASLR slide happen after the read
(`boot/bhaskixboot/src/main.rs`, read at the kernel load, slide later), so the measured bytes are
the file's — the same on every boot, which is what lets a verifier predict them.

### The protocol, from its definition

From EDK2's `MdePkg/Include/Protocol/Tcg2Protocol.h` (the TCG EFI Protocol Specification's reference
implementation; the TCG's own PDF is behind a browser challenge): `EFI_TCG2_PROTOCOL_GUID` is
`{0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}}`; the protocol is a
table of seven function pointers, `GetEventLog` second and `HashLogExtendEvent` third;
`HashLogExtendEvent(This, Flags, DataToHash, DataToHashLen, EfiTcgEvent)` takes an `EFI_TCG2_EVENT` of
`{UINT32 Size; {UINT32 HeaderSize; UINT16 HeaderVersion = 1; UINT32 PCRIndex; UINT32 EventType}; UINT8 Event[]}`,
packed; `GetEventLog(This, Format, &Location, &LastEntry, &Truncated)` with
`EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 = 2`, the crypto-agile log. Events the firmware logs after
`GetEventLog` go to the **final events table** (`{0x1e2ed096, 0x30e2, 0x4254, …}`), which the loader
copies too.

`efi.rs` gains the GUID as one more `const` beside the seven it has, and a `locate_protocol` helper
(today it is called inline twice). **No protocol is not a failure**: the loader records *no TCG2
protocol* and boots, because measured boot is evidence, and a machine without a TPM is a fact to
report rather than a reason to refuse.

### The handoff — version 3

`Handoff` gains one field, and `HANDOFF_VERSION` goes from 2 to 3, as its own doc comment requires for
any change of layout:

```rust
pub measurement: Measurement,

pub enum Measurement {
    /// The loader did not try — the Limine path, which measures nothing.
    NotAttempted,
    /// The loader looked and the firmware had no TCG2 protocol.
    NoTpm,
    /// Measured; the log as the firmware returned it, copied into loader-owned memory.
    Measured { log: &'static [u8], truncated: bool, final_events: &'static [u8] },
}
```

The log is **copied** into the handoff block before `ExitBootServices`, because the firmware's copy
may sit in boot-services memory the kernel will reclaim. The block is 32 pages today with its stack top
at `0x20000`; the log gets a bounded region and a log too large for it is truncated *and says so*.
Five literals construct `Handoff` (`boot/handoff/src/lib.rs` tests, `boot/shim/src/limine.rs`,
`boot/bhaskixboot/src/handoff.rs`, `mm/src/bump.rs`, the kernel's static copy) and two gates match
the literal `handoff version 2`; all change in the same step. **The Limine path reports
`NotAttempted`**, and the boot report says so in those words: an unmeasured boot must never be
mistaken for a measured one that found nothing wrong.

### The kernel reads the log; a service reads the TPM

**The log parser** is a leaf crate, `tcglog`, host-tested and fuzzed (`coding-style.md` §8: the log is
firmware data on the boot path, and a parser of it is a parser of untrusted input). It walks the
crypto-agile format — the spec-ID header event, then `TCG_PCR_EVENT2` records — and yields
`(pcr, event type, digests per bank, data)`. It computes nothing.

**The TPM service**, `bin/tpmd`, follows `bin/ahcid`'s shape: the kernel finds the device and the
domain drives it ([RFC 0075](0075-a-driver-that-is-not-in-the-kernel.md)'s *every other driver is a service*). The
kernel parses the ACPI **`TPM2`** table (nothing parses it today; `arch/x86_64/src/acpi.rs` gains a
pure parser beside `madt`, `dmar` and `mcfg`), reads the start method — **6 TIS, 7 CRB** (EDK2
`Tpm2Acpi.h`) — and mints `Frame` capabilities for the interface's MMIO page(s) and nothing else.
`tpmd` speaks CRB or TIS by polling (no interrupt is needed for a command a boot issues a handful of
times), and answers one request: `TPM2_PCR_Read` for the banks and PCRs asked. It holds no other
authority, and **no `TPM2_PCR_Extend`** is reachable through it in this RFC: a service that could
extend a PCR could write the record this RFC exists to keep.

### Agreement: replaying the log

The report's question — *do the log and the TPM agree?* — needs SHA-256: a PCR is
`SHA-256(PCR ‖ digest)` folded over its events. **The tree already has one**: `pkg/src/sha256.rs`,
RFC 0030's content identity, written to FIPS 180-4 and held to the four published test vectors, which
[RFC 0040](0040-where-cryptography-comes-from.md) lists as existing and classes as *a digest over
public data*. A replay is exactly that — PCR values and logged digests are public, and nothing secret
is hashed — so it decides nothing RFC 0040 has left open. **Where it runs** follows the dependency
layers `tools/check-deps.py` enforces: `tcglog` stays a leaf and takes the hash as a parameter, and
the replay runs in `bin/tpmd`, a program, which may depend on `bhaskix-pkg`; the kernel prints the
verdict `tpmd` returns.

### The boot report

One line, coloured as the report is (green, red FAILED), and always printed:

```
    measured boot  kernel, initrd, cmdline into PCR 9/9/8; 41 events, log and TPM agree (sha256)
    measured boot  NOT MEASURED -- this loader does not measure (Limine path)
    measured boot  no TPM: the firmware has no TCG2 protocol, so nothing was recorded
```

### Concurrency, failure and `unsafe`

The loader is single-threaded before `ExitBootServices`. The new `unsafe` is the protocol call
through a firmware function pointer, the same kind as the loader's existing `handle_protocol` and
`locate_protocol` calls, and the log copy out of firmware memory. In `tpmd`, MMIO through
`Mmio<T>` as `bin/ahcid` does. A TPM that does not answer within a bounded poll is reported, not
waited on: the boot continues and the line says *TPM did not answer*.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Measure in the kernel instead of the loader | A kernel measuring itself records what the attacker wrote, written by the attacker: the root must be an earlier stage | Never, for the kernel image; runtime measurements (programs, configuration) are a later RFC and do belong after the kernel |
| Do the whole chain at once, signing included | Signing without key custody repeats RFC 0030's refusal one layer down; the lead sequenced measurement first | Key custody is decided — then signing is the next RFC |
| Measure on the Limine path too | Limine boots the BIOS lanes and the existing UEFI lanes, and it is the incumbent this project is replacing ([RFC 0028](0028-bhaskixboot.md)); making an upstream loader measure is that project's work, and whether Limine can is not checked here. The BIOS path's TCG interface is a different one again | A target can boot only through Limine and needs measuring |
| TPM driver in the nucleus | Small, but the project's practice is services ([RFC 0075](0075-a-driver-that-is-not-in-the-kernel.md)), and a TPM is touched a handful of times a boot — no latency case | A nucleus consumer needs it before services start, e.g. unsealing a key the kernel itself needs |
| Replay through the TPM's own `TPM2_Hash` | A command per event, slower by orders of magnitude on a real TPM, to avoid a hash the tree already has and already trusts for public data. (The first draft chose this, believing the tree had no SHA-256; it has had one since RFC 0030.) | The only active bank is one the tree has no implementation of — SHA-1 or SHA-384 — and checking it matters more than adding that hash |
| DRTM (Intel TXT / `GETSEC[SENTER]`) | A dynamic root removes firmware from the chain, which is stronger; it is also vendor-specific, needs an ACM blob, and is not what T6 asks for | Firmware compromise (security.md's SMM row) moves in scope |

## Impact on existing design documents

- [security.md](../security.md) §3 — its diagram has **Limine** measuring PCRs 8–9, which was never
  true and is the wrong loader now: it becomes `bhaskixboot.efi`. T6's status moves to *measured,
  not enforced*; gap 1 stays open and its text says why.
- [architecture.md](../architecture.md) — the `Handoff` listing gains `measurement`, and the version
  line reads 3.
- [driver-model.md](../driver-model.md) — Phase 3 item 12, *TPM 2.0 (CRB/TIS)*, is this RFC's
  `bin/tpmd`.
- [roadmap.md](../roadmap.md) — the *Secure boot chain* row: TPM driver and handoff bump done when
  this lands; key custody still open.

## Security implications

- **What it gives**: a record, in hardware that software cannot roll back, of the loader, the kernel,
  the initrd and the command line of every native boot — the input remote attestation (T8) and
  sealing need. **What it does not give**: prevention. A replaced kernel still runs; it is
  *detectable* by anyone who reads the PCRs or the log, not stopped. T6 stays open, said so.
- **New authority**: `bin/tpmd` holds the TPM's MMIO and answers PCR reads. PCR values are not secret
  — they are what a quote reports — but `tpmd` must not offer extend, clear, or any hierarchy
  command; the request set is closed and gated.
- **New untrusted input**: the event log (firmware-provided, on the boot path) and the ACPI `TPM2`
  table. Both parsers are pure, host-tested, and fuzzed before merge.
- **A lie the report must not tell**: *no TPM* and *not measured* are different sentences from *log
  and TPM agree*, and a gate holds each.

## Performance implications

Hashing about 16 MB in firmware — a 12.5 MB kernel ELF and a 3.3 MB initrd, measured 2026-10-07 — before `ExitBootServices`: measured on the step that
adds it, reported in the loader's own timing, not guessed. Replay is a few dozen SHA-256 compressions
in ring 3, and the PCR read one TPM command per bank; swtpm and a real TPM differ by orders of
magnitude, so both are measured. No cost on any
path after boot.

## Testing plan

- **Host**: `tcglog` against a log captured from OVMF + swtpm (checked in as a fixture), plus
  hand-built logs for every refusal; the `TPM2` table parser the same way; the `Handoff` validation
  for version 3; the request-set closure of `tpmd`'s protocol. A fuzz target over `tcglog`.
- **QEMU**: a native lane with `-tpmdev emulator` (verified present in this QEMU, 4.2.1) and
  `-device tpm-crb`, backed by **swtpm built here from pinned, checksummed sources into `build/`**
  (Ubuntu 20.04 does not package it), the device line in `tests/qemu/devices.sh` as the one-machine
  gate requires. Gates: the measured line; a kernel byte changed on the ESP changes PCR 9's digest
  (armed red); TPM absent → *no TPM*; Limine lane → *NOT MEASURED*. **First of all, measure whether
  Ubuntu's `OVMF_CODE_4M.fd` exposes `EFI_TCG2_PROTOCOL` at all** — a firmware built without TPM 2.0
  support has none, and that is learned by booting, not by reading.
- **CI**: a new native-with-TPM job installing swtpm from the runner's packages — the first native
  lane CI runs at all.
- **Hardware**: the SR550's TPM reports **1.2** and its interface is a firmware setting
  (`InterfaceTypeSelection: BiosSetting`, Redfish, 2026-10-07); switching it to 2.0 is the lead's
  call at the time. **And the native loader must first complete a boot there**, which it has not
  since 2026-08-22.

## Unresolved questions

1. **`EV_IPL` or `EV_EVENT_TAG`** for the loader's events — the PC Client profile decides, and it
   must be read rather than recalled. Step 1 also records how `tpm2_eventlog`-style tooling decodes each.
2. **Banks the tree cannot hash** — a firmware with only SHA-1 or SHA-384 active leaves nothing for
   `pkg`'s SHA-256 to replay; the report then says *not checked* and why, and whether to add a hash
   for it is a decision for the day a machine needs it.
3. **Which banks** — SHA-256 only, or whatever the firmware has active; the log says which, and the
   report should say which it checked.
4. **Attestation format** (security.md §10: DICE or RATS/EAT) — out of scope here; this RFC only
   produces what any of them would consume.

## Implementation plan

1. **The test bed, and the first measurement**: swtpm and libtpms built here from pinned sources;
   the device line in `devices.sh`; boot the native lane with a TPM and record whether OVMF offers
   `EFI_TCG2_PROTOCOL`. If it does not, this RFC stops and says so. **Measured 2026-10-07: it does.**
   The test bed became a container instead (the lead's choice): `tools/swtpm.sh` runs Ubuntu
   24.04's packaged `swtpm` 0.7.3 — the build CI's `ubuntu-24.04` runner installs — pinned by image
   digest and package version, with QEMU on the host reaching it through a socket. A temporary
   loader probe (never committed) that called `LocateProtocol` with the TCG2 GUID read **`protocol
   present`** under this host's `OVMF_CODE_4M.fd` (Ubuntu's `0~20191122.bd85bf54-2ubuntu3.6`) with
   `-device tpm-crb` backed by that emulator, and **`protocol absent`** on the same boot without the
   device — so the probe told the two apart. The firmware's own changelog never mentions a TPM, which
   is why this was booted rather than read. **And the lane**: `qemu_tpm_args` in `tests/qemu/devices.sh`
   (the one-machine gate allows a `-device` line nowhere else) and `BHASKIX_TPM=1` in
   `native-boot-test.sh`, which starts a fresh emulator before each of its two boots and stops it
   on exit — `make test-boot-native-tpm`. With the TPM attached the lane passed all 24 of its checks,
   as it does without, and the emulator's state file was written during the boot, so the firmware
   drove the TPM rather than ignoring it. **Not in `make test`** until step 2 gives it something to
   assert, because it needs Docker. **Step 1 is done.**
2. **The loader measures**: GUID, `locate_protocol`, three `HashLogExtendEvent` calls, a report
   line from the loader. ~~Gated: digest changes with the kernel byte, armed red.~~ **Done 2026-10-07**,
   and the gate is not the one written here: `HashLogExtendEvent` returns no digest, so nothing a
   step-2 boot prints can show one changing — that gate moves to step 3, where the log is read. What
   step 2 gates is the loader's own account: with a TPM, `measured kernel into PCR 9`, `initrd into
   PCR 9` and `cmdline into PCR 8` and no refusal; without one, `no TCG2 protocol; nothing is
   measured`. Both armed red by a loader that skipped the call (*measured 0 of 3*, and the silence
   the plain lane now refuses). The event bytes are built by `bhaskix-tcglog::tagged_event`, a leaf
   at `unsafe` budget zero whose layout test was armed red by a one-byte header; the loader's budget
   went from 114 to 125 for the protocol's lookup and call. `make test-boot-native-tpm` joined
   `make test`, saying `skip` where there is no usable docker.
3. **The handoff carries the log**: `HANDOFF_VERSION` 3, `Measurement`, the five literals and two
   gate literals, the Limine path's `NotAttempted`. **And the gate step 2 could not have**: the
   kernel's digest in the log changes when one byte of the kernel on the ESP does, armed red.
4. **`tcglog`**: host-tested, fuzzed, a captured fixture; the kernel prints the events it found.
5. **ACPI `TPM2` and `bin/tpmd`**: PCR read only, closed request set, gated.
6. **Agreement**: replay with `pkg`'s SHA-256 in `bin/tpmd`; the report's verdict, each outcome gated.
7. **CI**: the native-with-TPM job.
8. **Hardware**: after the native loader boots the SR550 and the lead switches its TPM to 2.0.
