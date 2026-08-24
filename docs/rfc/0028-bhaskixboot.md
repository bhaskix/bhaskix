# RFC 0028: `bhaskixboot.efi` — the machine enters through our own door

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-18**, all seven steps implemented — accepted on the working demonstration: the native lane answers the full Limine-lane gate set (74 gates, both loaders, same list — `tests/qemu/boot-test.sh native`), the loader-specific lane holds its 23 plus the permanent negative arm, and the roadmap bullet is closed. **The figure "74 gates" is on the hand-maintained scale retired 2026-08-24 and is left as it was; the *claim* it carries — parity between the two loaders — was re-checked on that date and holds: 107 passing assertions on each lane, same list, by the command in TRACKER's header.** Question 2 was answered against its own sketch — bring-up lives in the kernel — and questions 1 and 3 closed with their steps (one hybrid-free ESP directory per lane; Secure Boot stays deferred to hardware, M1-17) |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | boot |
| **Milestone** | Phase 2 — the roadmap's `bhaskixboot.efi` bullet, and half of the phase's exit criterion ("boots on its own bootloader") |
| **Depends on** | [docs/architecture.md](../architecture.md) §1 (the shim boundary this cashes in), `bhaskix_boot::Handoff` (the contract that *is* the native protocol), [RFC 0021](0021-unpredictability.md) (the KASLR draw, when its step arrives) |

---

## Summary

**A UEFI loader of our own, and the native boot protocol is the `Handoff` we already own.** A
freestanding UEFI application — hand-rolled firmware bindings, no external crates, the same
policy `boot/shim/src/limine.rs` set — reads the kernel ELF, the initrd and the command line
from the boot volume, takes the machine's shape from the firmware (memory map, framebuffer,
ACPI, SMBIOS), builds the higher-half page tables, loads the kernel W^X, and enters it through
a **second front door in the shim**: `bhaskixboot_start`, taking a loader-built `Handoff`
precursor. Nothing in `kernel/` changes, because nothing in `kernel/` ever named a bootloader —
that was the point of the shim boundary from Phase 0, and this RFC is that investment cashed
in. Limine stays the default on every existing lane while the native lane earns parity, gate
by gate; sovereignty is declared when the native lane runs the same gates, not when the binary
first links.

## Motivation

**The roadmap has carried this bullet since Phase 0, and the phase's exit criterion names it**:
"boots on its own bootloader". The shim boundary was designed so this day would cost a loader
and not a kernel: `docs/architecture.md` §1 isolates Limine behind `Handoff` precisely so that
"native `bhaskixboot.efi`, scheduled for Phase 2" would slot in behind the same struct.

**Sovereignty is a concrete property here, not a flag.** Today the first code that runs on
every boot is a third-party loader speaking a protocol this project does not control: base
revisions can move (the shim already refuses revision drift), features arrive on the loader's
schedule, and the one component nothing downstream can verify is the one that arranges all of
memory. A loader in this tree is a loader under this tree's rules — the `unsafe` budget, the
fuzz-hardened parsers, the boot gates, the vendor-string check, all of it.

**What happens if we do nothing:** Phase 2 cannot exit, and the project's first instruction on
every machine remains someone else's.

## Design

### The native protocol is the `Handoff`

There is no new wire format and no request/response negotiation. The loader builds the same
`bhaskix_boot::Handoff` the shim builds today — version-stamped, refused on mismatch by the
existing check — and enters the kernel binary at a dedicated symbol:

```text
bhaskixboot_start(handoff: &Handoff) -> !
```

with the entry contract stated once and asserted where possible: 64-bit long mode; interrupts
off; boot services exited; the loader's page tables live with (a) the higher-half direct map at
the same base the kernel expects, (b) the kernel's segments mapped at its linked (later: slid)
virtual base with W^X honoured, and (c) the `Handoff` and everything it references — memory
map, initrd, strings — in memory marked `BootloaderReclaimable`, exactly as the Limine path
marks them; a 64 KiB stack; no secondary CPU started unless `start_secondaries` says the
loader can. The shim's Limine door stays as it is; the two doors converge on `kernel_main`
within a dozen lines, and the `loader` field says which door was used, which is what makes the
lanes distinguishable in every report.

### Firmware bindings: hand-rolled, minimal, refused loudly

The `uefi` ecosystem crates are not used — the external-dependency allowlist is empty on
purpose, and a boot loader is the worst possible place for the first exception. The
application defines exactly the protocol surface it consumes: system table, boot services
(memory map, allocate, exit), simple file system on the boot volume, GOP for the framebuffer,
and the configuration-table walk for ACPI and SMBIOS. Every firmware answer is treated as
hostile input — bounds-checked, version-checked, refused with a printed sentence rather than
trusted — because firmware is exactly as trustworthy as a disk image, and this project fuzzes
those.

### What the loader reuses, and what that forces

The kernel ELF is parsed by the **same fuzz-hardened parser the kernel runs** — 10.97 billion
executions of assurance do not get rewritten. That parser lives in `kernel/src/elf.rs` today,
where a UEFI application cannot reach it; it moves to a leaf crate (`elf/`, layer −3 beside
`fs` and `net`, zero `unsafe`, the fuzz target repointed) in a step of its own, kernel
behaviour identical by the suite. The loader links `bhaskix-boot` (the `Handoff` types),
`bhaskix-elf`, and — when the KASLR step arrives — `bhaskix-rand` for the slide draw, RFC 0021
policy included: a machine that cannot be unpredictable boots unslid and *says so*.

### Parity is graduated, and the graduation is written down

A new harness mode boots OVMF with `bhaskixboot.efi` instead of Limine. Its gate set starts
small — sign of life, payload integrity — and grows with the steps below; the lane's gate
list at any moment *is* the honest statement of how far sovereignty has come. Two reductions
are expected to persist past the first entry and are stated now rather than discovered:
**secondary CPUs** (the kernel already answers a loader that cannot start them — "loader
reported no way to start secondaries" — so the native lane boots one CPU until the parking
gap closes; *closed at step 7, and not as sketched here: the kernel grew its own INIT-SIPI,
see unresolved question 2*) and **KASLR** (unslid until the draw step; the lane's gate
accepts "unslid, and said so" only while that step is pending — *closed at step 7: the
loader draws, and the lane demands the kernel confirm the slide*). Phase 2's
exit criterion is met when the native lane runs the **same gates as the Limine lanes** — 48
when this was written, 74 by the day parity arrived, because the suite kept growing and
parity was measured against the suite as it stood — and not before.

### What does not change

- **Every existing lane keeps booting Limine** until native parity is demonstrated, and
  Limine remains in-tree afterwards as the BIOS path — `bhaskixboot` is UEFI-only by name
  and by scope, and BIOS machines are still real.
- **The kernel.** No `kernel/` source line changes for any step of this RFC except the elf
  crate extraction, which moves code without changing it.
- **The Limine containment gate** (only `boot/` may name it) stands unchanged; the native
  loader lives under `boot/` too.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Implement the Limine protocol in our loader** (existing shim door unchanged) | Sovereignty from a protocol is not achieved by reimplementing it: the project would then maintain someone else's contract forever, revision drift included. The shim boundary exists so the native protocol could be the `Handoff` itself | Never — it inverts the point |
| **Use the `uefi`/`uefi-rs` crates** | The external allowlist is empty on purpose, a supply-chain rule (`security.md` §1) worth most exactly here, in the first code that runs. The surface actually consumed is small enough to own | The consumed surface growing past what a fuzz-and-review budget covers — and secure boot signing tooling, if it ever needs more, is build tooling, not linked code |
| **A separate kernel entry binary rather than a second shim door** | Two kernel binaries on one image drift; the shim already exists to own entry translation, and a second door in it is a dozen lines beside the first | Never |
| **Skip BIOS-lane retirement debates by making bhaskixboot do BIOS too** | A BIOS stage-1/stage-2 loader is a different, larger project with none of UEFI's services; Limine already covers it and stays | The day BIOS machines stop mattering to the project — recorded then, not assumed now |
| **Wait for physical hardware (M1-17) first** | The loader is testable under OVMF today — the harness lane exists — and hardware, when it arrives, tests firmware quirks better with our loader already mature | — |

## Impact on existing design documents

- **[architecture.md](../architecture.md)** §1 — "Native `bhaskixboot.efi` scheduled for
  Phase 2" becomes a description of the two doors and the entry contract, updated when the
  entry step lands, not before.
- **[roadmap.md](../roadmap.md)** — the bullet's ✅ waits for gate parity, per the graduation
  rule above; intermediate steps update TRACKER only.

## Security implications

- **New parser surface, all of it hostile-input**: firmware tables, the boot volume's
  filesystem structures, GOP mode data. Each gets the same treatment the tree's parsers get —
  bounds-checked safe code, refusal over trust — and the ELF path reuses the already-fuzzed
  parser. The FAT-read surface is deliberately minimal (read the files the config names; no
  write support, ever).
- **`unsafe` budget**: the loader crate carries its own, measured per step; the UEFI calling
  convention and the final jump are its irreducible core.
- **KASLR**: temporarily absent on the native lane, stated by the lane's own gate text —
  never silently.
- **Secure Boot**: out of scope for this RFC and said so; an unsigned loader on a Secure Boot
  machine is refused by firmware, which is that machine's policy working. Signing is its own
  future conversation.

## Performance implications

None that matter: boot-time work, once per boot. The lane's boot-to-gates wall time is
recorded beside the Limine lanes' as a curiosity, not a gate.

## Testing plan

- **Host**: the ELF crate's tests and fuzz target move with it, unchanged. The loader's pure
  logic — the memory-map translation to `MemoryRegion`s (the same truncation honesty the shim
  has), the page-table construction arithmetic, the config parse — is host-tested; the
  translation gets the edge-seeded harness treatment.
- **QEMU/OVMF**: the native lane, growing per step as above; the negative arm at the entry
  step is a corrupted kernel image, which the loader must refuse with its reason printed
  rather than jump into.
- **Real hardware**: this RFC is M1-17's other half — when a machine arrives, the native
  loader is what the project boots on it. Until then, OVMF is the firmware the design is
  tested against, and the record says so.

## Unresolved questions

1. **Where the native lane's ISO/ESP layout lives** — one hybrid image carrying both loaders,
   or a second image for the native lane. Decided in step 1 by whichever keeps
   `make test` one target.
2. **Secondary-CPU parking** — ~~the loader's INIT-SIPI step needs a real-mode trampoline; how
   much of `kernel/src/smp.rs`'s existing bring-up knowledge is shareable is decided when
   that step is reached.~~ **Answered at step 7, against the sketch**: the trampoline lives in
   the *kernel*, not the loader. A loader-side implementation cannot satisfy the
   `start_secondaries` contract — the function pointer would name loader code at identity
   addresses that stop being mapped the moment the kernel leaves the boot tables — and
   parking loader-started CPUs would put their whole world in reclaimable memory. So the
   loader keeps offering `None`, honestly, and `smp.rs` answers `None` by doing the work
   itself: processors enumerated from the MADT, a real-mode trampoline
   (`bhaskix_arch::mp`) copied to a page reserved below one megabyte at boot, INIT-SIPI-SIPI
   from the bootstrap CPU, and every stack handed over through an atomic mailbox a released
   processor must *win* — because under emulation a processor can arrive seconds late, and a
   late processor reading repatched slots was a shared stack and a stolen identity (each CPU
   derives its own from `CPUID` instead). This road works for **any** loader that cannot
   start secondaries, which is a stronger property than the sketch had.
3. **Secure Boot signing** — deliberately out of scope; revisited when physical hardware
   (M1-17) makes it concrete.

## Implementation plan

1. **The skeleton and the lane**: the `boot/bhaskixboot` crate on `x86_64-unknown-uefi` (the
   toolchain file grows the target), hand-rolled system-table bindings, serial-and-console
   banner; the harness mode boots it under OVMF and demands the banner. Sign of life,
   provably ours.
2. **The payload**: simple-filesystem bindings; read kernel, initrd and config from the boot
   volume; print sizes and a checksum; the gate compares the checksum against the build's.
3. **The machine's shape**: memory map, `exit_boot_services`, GOP, RSDP, SMBIOS — translated
   into `MemoryRegion`s with the shim's truncation honesty, printed for the gate.
4. **The elf crate extraction**: `kernel/src/elf.rs` becomes `bhaskix-elf` at layer −3, fuzz
   target repointed, kernel identical by the full suite. Worth doing alone; nothing else in
   this plan changes the kernel.
5. **The load and the tables**: HHDM and kernel mappings built, segments placed W^X, the
   `Handoff` assembled in reclaimable memory.
6. **The entry**: `bhaskixboot_start` in the shim; the native lane boots to `kernel_main`,
   single CPU, unslid, both stated; the corrupted-image negative arm watches the refusal.
7. **Parity, in whatever order the gaps demand**: secondaries, KASLR (RFC 0021's draw), then
   the lane adopts the full gate set and the roadmap bullet closes.

Steps 1–3 touch nothing outside `boot/` and the harness; step 4 is the one kernel-adjacent
move, alone on purpose.
