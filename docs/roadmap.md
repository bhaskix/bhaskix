# Bhaskix — Roadmap

*Status: living document. Milestones are ordered by dependency, not dated.*

*This file owns **scope** — what each milestone is and how it is judged. It does not own status:
[TRACKER.md](../TRACKER.md) does, and where the two disagree about what is done, TRACKER wins. The
status markers here are a summary of it and nothing more.*

We do not publish dates for *engineering* milestones. An unfunded volunteer kernel project that
publishes dates publishes disappointments. What we publish instead is **ordering** and **exit
criteria**: a milestone is done when its criteria pass in CI, and not before.

Every milestone has an exit criterion that a stranger can verify by running a command.

**One exception, set deliberately by the project lead: the first release has a date.** A release is
not an engineering milestone — it is a decision to stop and publish what exists — and a dated one
forces the questions a date is good at forcing: what is in, what is out, and what the honest gaps
are on the day. See [First release](#first-release--29-november-2026) below. The scope is written to
fit the date rather than the date stretched to fit an ambition, and if the criteria are not met the
project publishes what it has *with the shortfall stated*, which is the only way a date and honesty
survive in the same document.

---

## Phase 0 — Design ✅ complete, except its review criterion

**Goal:** every load-bearing decision written down before it is made accidentally in code.

| Item | Status |
|---|---|
| [vision.md](vision.md) | ✅ adopted |
| [architecture.md](architecture.md) | ✅ draft — needs review |
| [memory.md](memory.md) | ✅ draft — needs review |
| [scheduler.md](scheduler.md) | ✅ draft — needs review |
| [security.md](security.md) | ✅ draft — needs review |
| [driver-model.md](driver-model.md) | ✅ draft — needs review |
| [ai-native.md](ai-native.md) | ✅ draft — needs review |
| [coding-style.md](coding-style.md) | ✅ adopted for Phase 1 |
| A1 license | ✅ [RFC 0001](rfc/0001-license-apache-2.0.md) — Apache-2.0 |
| A2 syscall ABI shape · A3 IPC style · A4 userspace ABI | ✅ [RFC 0008](rfc/0008-syscall-and-ipc-shape.md) |
| A5 5-level paging (LA57) | ✅ [RFC 0025](rfc/0025-four-level-paging-on-purpose.md) — four-level on purpose, five behind written triggers |
| Dev environment reproducible (`tools/setup-dev.sh`) | ✅ |
| CI: build, fmt, clippy, host tests, QEMU boot | ✅ |
| Design-document review by two people who did not write them | ⬜ **outstanding** |

**Exit criterion:** a new contributor clones the repo, runs `tools/setup-dev.sh && make run`, and
gets a QEMU window. Documents reviewed by at least two people who did not write them.

**The first half passes; the second does not.** The documents have one author and no independent
reviewers, so Phase 0's exit criterion is genuinely unmet — recorded here rather than quietly
marked complete. It does not block code, and it should be closed before the architecture calcifies.

**Correction, kept because it was wrong here for a long time.** This table listed A1–A5 as one row
blocking *M1 exit*. They never blocked M1, which is boot and output and touches none of them; A1
blocked *accepting external contributions*, and was settled before any arrived. A2, A3 and A4 were
answered together by RFC 0008 — A4 by refusing its premise, since the native ABI *is* the syscall
interface. A5 closed 2026-08-16 with RFC 0025 — this paragraph said "A5 is the one still open"
until 2026-08-18, two days stale, found while closing RFC 0029. No architecture question is open.

---

## Phase 1 — Foundation ✅ complete

### M1 — Boot and output ✅ *(18/18 — M1-17 **met 2026-08-23**: the boot report was read off a Lenovo SR550, 19,550 bytes over serial-over-LAN)*

*Vision milestone 1: "Boot with UEFI, print Hello from Bhaskix".*

- Limine boot on UEFI (and BIOS, which comes free)
- `boot/` shim → `bhaskix_boot::Handoff`
- Serial (16550) driver — the debugging lifeline, written first
- Framebuffer text output from the handoff
- `panic_handler` that prints to serial and halts
- Build system: `make`, `make run`, `make test`; bootable ISO via `xorriso`

**Exit:** `make run` prints `Hello from Bhaskix` to both serial and framebuffer, on UEFI and BIOS,
on QEMU, and boots on at least one piece of real hardware.

### M2 — CPU state and interrupts ✅

*Vision milestone 2.*

- GDT, TSS, per-CPU data, IST stacks for double-fault and NMI
- IDT, all 32 CPU exceptions with useful register dumps
- Local APIC, IO-APIC, APIC timer
- ~~`arch::Arch` trait boundary defined~~ — **deferred at M2 on 2026-08-03, and this bullet said
  otherwise until 2026-08-20.** A portability trait written with one implementation and no second
  architecture in sight documents today's code instead of constraining tomorrow's; it is written
  when AArch64 work begins. There is no `trait Arch` in the tree. What is enforced instead is the
  crate dependency direction, in CI ([architecture.md](architecture.md) §7)
- Boot-time bump allocator ([memory.md](memory.md) §1)

**Exit:** every exception vector produces a clear diagnostic instead of a triple fault. A test that
deliberately triggers a page fault, a GP fault, and a double fault reports all three correctly and
does not reboot the machine.

### M3 — Memory management ✅

*Vision milestone 3.*

- Frame database; buddy PMM with per-CPU magazines; `DMA32` zone
- `AddressSpace`, `RangeMap`, 4-level page tables, W^X, NX
- Slab allocator as `GlobalAlloc` — `Box`/`Vec`/`BTreeMap` work
- Demand paging, COW, guard pages, `copy_{from,to}_user` with fixups
- KASLR

**Exit:** host property tests for buddy and slab pass; the **frame-leak test** (create/destroy 1000
address spaces, assert free-frame count returns exactly to baseline) passes in QEMU; `alloc` types
usable throughout the kernel.

### M4 — Threads and scheduling ✅

*Vision milestone 4.*

- `Thread`, `Context`, kernel stacks with guard pages, `bhaskix_context_switch` in asm
- Per-CPU runqueues, Fair class (virtual deadline), Idle class
- SMP bring-up (AP trampoline, per-CPU init)
- Lock ranking infrastructure, active in debug builds
- Timers: APIC deadline mode, timer wheel, tickless idle

**Exit:** N threads across M CPUs, 10⁷ ping-pong iterations, no lost wakeups, no stranded threads,
lock-rank assertions clean. Fairness test: two equal-weight workloads get 50/50 ± 2%.

### M5 — Domains, capabilities, syscalls, user mode ✅

*Vision milestone 5.*

- Capability objects, CSpace, derive/revoke with transitive revocation
- `Domain` with `ResourceEnvelope`
- `SYSCALL`/`SYSRET` entry, syscall dispatch, SMAP bracketing — the interface is
  specified by [RFC 0008](rfc/0008-syscall-and-ipc-shape.md) (accepted): six syscall
  kinds, all authority arriving as a capability argument
- Ring 3 execution
- Synchronous IPC (call/reply) with badges

**Exit:** a user-mode program runs, invokes capabilities, is denied what it does not hold, and is
killed cleanly when it faults. A test asserts transitive revocation completes before the syscall
returns. Two domains cannot see each other's memory — verified, not assumed.

### M6 — Filesystem, ELF, shell ✅ *(complete — the ELF loader's 24 hours of fuzzing was met 2026-08-13)*

*Vision milestone 6.*

- VFS layer; a simple on-disk filesystem (initially read-only, `initrd`-backed)
- ELF64 loader — with a fuzz target, per [coding-style.md](coding-style.md) §8
- Kernel shell, then a user-mode shell over the syscall interface
- virtio-blk driver

**Exit:** boot to a shell, `ls` a real filesystem, load and run an ELF binary from disk. The ELF
loader survives 24 hours of fuzzing without a crash.

**Phase 1 complete.** Bhaskix is a real, if minimal, operating system: it boots, schedules threads
across four CPUs, runs programs in ring 3 that hold capabilities and nothing else, and answers a
user-mode shell from services in their own domains.

**Every exit criterion is met**, M1-17 last, on 2026-08-23. It took three boots of a Lenovo SR550.
The first (2026-08-22) was observed on screen and captured nothing. The second captured the
firmware's output and then silence. The third read the `serial` line back with `dmesg`
([RFC 0042](rfc/0042-reading-the-boot-report-back.md)) — and that line said `present`, which meant
the kernel had found a UART, believed it worked, and was writing to a port nobody carried. **The
machine has two serial ports and this kernel only ever probed one.** Writing to both put 19,550
bytes of boot report on serial-over-LAN.

The criterion was never "a machine" — it was a boot whose report somebody read, and it stayed open
for exactly as long as that was impossible.

**Correction, 2026-08-20.** This paragraph and M6's heading both said the ELF loader's 24 hours of
fuzzing was still owed. It was **met on 2026-08-13** — three campaigns ran the full twenty-four
hours: 10.97 billion executions over `elf::parse`, 11.34 billion over `DMAR`, 52 million over
`ustar`, with no crash, no hang and no artifact. `TRACKER.md` recorded it that day and this file did
not, for a week. The claim is corrected here rather than deleted, because a roadmap that
under-reports is wrong in the same way one that over-reports is.

---

## Phase 2 — Core Operating System 🔨 current

Order within the phase is flexible; dependencies are noted. Done so far — see
[TRACKER.md](../TRACKER.md) §4 for the detail: shared memory and notifications, the service
framework, IOMMU discovery and per-device domains, the driver framework, the full VFS, and process
management. Networking runs through TCP, both directions, measured, and programs speak it
through `bhaskix-sock` rather than hand-rolled exchanges. The telemetry plane runs — typed
events, per-CPU rings, a live reader. The machine boots on its own loader — `bhaskixboot.efi`,
held to the same gates as the incumbent. Packages exist — the image is a function of
reviewable manifests, and programs install, run and remove at the shell with grants
derived from what their manifests ask. What remains is libc.

**Two debts were owed inside this phase and are not bullets, because they are not new scope.**
[coding-style.md](coding-style.md) §8 binds this project to a fuzz target *before* an
untrusted-input parser merges, and two parsers merged without one: the **filesystem** (a hostile
disk image — and journal replay runs before anything can refuse) and **IPv6/NDP** (covered by the
seeded mutation harness, which is a weaker mechanism and is not the same one). **The filesystem's
was paid on 2026-08-21** — `fuzz/fuzz_targets/fs_image.rs`, four arms, 123,501 executions clean, and
every path in it proven reachable by a deliberate panic rather than assumed from a coverage number.
IPv6/NDP is still owed. Both are tracked as tasks in [TRACKER.md](../TRACKER.md) §4 rather than
scheduled here — promoting a merge-gate obligation to a phase item would turn a rule into a plan.

- ✅ **Process management** — [RFC 0017](rfc/0017-process-management.md), steps 1–6 implemented,
  M9-18 … M9-23. Capability-shaped rather than POSIX-shaped: no `fork` (it duplicates a capability
  space by implication, which is ambient authority through the back door), no pid (the process tree
  *is* the capability tree), no signals ("stop" is `KILL` on a capability you hold). **The
  supervisor this row said was still owed exists**, in ring 3 — a program creates a domain, grants
  it authority one piece at a time, starts a program in it, and reaps it. What is *not* done is the
  fourth question the implementation raised: whether a domain should end when its last thread exits,
  which needs the boot sequence to stop treating a domain as outliving its threads
- ✅ **Full VFS** — [RFC 0015](rfc/0015-filesystem.md) and
  [RFC 0016](rfc/0016-capability-in-a-reply.md), both implemented. A writable filesystem with a
  journal and a page cache, running as a service in its own domain. The RFCs separate three things
  usually described as one: a namespace that is not ambient — **the ambient root is gone**, a
  directory is a badged capability the kernel stamps, and there is no way up out of one; a journal
  whose claim is tested by interrupting the machine at every write rather than argued for; and a
  page cache built after the journal, because the journal decides when a dirty page may go home
- ✅ **Shared memory and notifications** — [RFC 0009](rfc/0009-shared-memory.md) and
  [RFC 0010](rfc/0010-notifications.md), both implemented: a `Memory` object a capability names, and
  a doorbell to go with it. Between them they complete RFC 0008's answer to A3, and they precede
  everything below: a service framework whose bulk paths move sixteen bytes per round trip is a
  framework nobody will measure twice
- ✅ **Service framework** — [RFC 0013](rfc/0013-service-framework.md), implemented. The
  `Service` trait, both placements, and the CI job that builds both (this is the milestone that
  makes
  [architecture.md](architecture.md) §2 true rather than aspirational). Its precondition is met:
  until the bulk paths used shared memory the two placements were identical *by accident*, because
  four registers map into nobody
- ✅ **IOMMU: discovery, per-device domains, strict mapping** — [RFC 0012](rfc/0012-iommu.md),
  implemented, **all seven steps**. Interrupt remapping is **on by default** from 2026-08-11, which
  retires RFC 0011's residual risk — a device raising an interrupt it was never programmed to raise;
  `iommu=no-remap-irq` is the way out on a machine where it goes wrong. VT-d first, because QEMU
  emulates it and a design CI cannot test will be wrong unnoticed; an AMD machine runs degraded and
  says so. This is what funds `security.md` §1 T3 and T4, and what unblocks a driver running outside
  the kernel
- ✅ **Driver framework** — [RFC 0014](rfc/0014-driver-framework.md), implemented. PCIe/ECAM
  enumeration, `register_block!`, `Mmio<T>`, mock-MMIO test harness. Its motivation is an invoice
  rather than a
  plan: the second driver — `bin/blkd`, in a domain — cost three bugs the first one had already
  learned and written down in comments, and a framework is the difference between a lesson recorded
  and a lesson enforced
- ✅ **Networking** — every word of the bullet's name real as of 2026-08-18, IPv6 last. **And every
  word of it rests on one machine, which this bullet did not say until 2026-08-24**: this system's
  only NIC driver is virtio (`bin/netd` drives that and nothing else, and the kernel has no network
  driver at all), *and* a network device is refused unless an IOMMU contains it — so QEMU's
  `intel-iommu` lane is the only machine, physical or virtual, where any of this has ever run. The
  SR550 has neither half: four Intel X722s and four IOMMU units off pending
  [RFC 0043](rfc/0043-an-iommu-on-a-machine-with-no-virtio.md). **Nothing here has run on physical
  hardware and currently cannot.** [RFC 0018](rfc/0018-networking.md)
  (accepted, all seven steps): virtio-net in a domain, Ethernet, ARP, IPv4, ICMP and UDP in a
  `no_std` crate with six fuzz targets, a socket that is a badged capability rather than a
  descriptor, DHCP by demonstration. [RFC 0020](rfc/0020-tcp.md) (implemented, all six steps): a
  pure host-tested state machine in `bin/tcpd`, RFC 6528 initial sequence numbers from
  [RFC 0021](rfc/0021-unpredictability.md)'s hardware draw, and a client program — `bin/tcpc` —
  that echoes sixteen bytes and thirty-two KiB both directions through **rings its own domain
  owns and hands over as capabilities** ([RFC 0022](rfc/0022-capability-in-a-call.md),
  implemented), outbound against a deterministic peer and inbound from a host-initiated
  connection, with handshake, round trip and throughput measured as distributions and every wait
  wake-driven ([RFC 0023](rfc/0023-a-wake-for-a-connection.md), accepted — the four TCP-era
  RFCs are all accepted, 0021 on 2026-08-14 and 0020/0022/0023 on 2026-08-16; this bullet
  said "await acceptance review" until 2026-08-18). The sockets API above what the services themselves speak exists since
  [RFC 0027](rfc/0027-a-sockets-api-worth-the-name.md) (accepted 2026-08-17): `bhaskix-sock`,
  the client crate `bin/dhcp` and `bin/tcpc` now speak through. [RFC 0029](rfc/0029-ipv6.md)
  (accepted 2026-08-18, all six steps) landed IPv6 as a second address
  family rather than a second stack: zero-`unsafe` parsers and NDP, SLAAC, UDP and TCP over
  the same rings and handover with the state machine untouched, dual stack gated on every
  networked boot, and both families measured on the same run — the v6 numbers through the
  loopback carry no emulator at all. **Not done, each with a written trigger:** off-box v6
  UDP/TCP peers and inbound v6 (this emulator has no v6 peer — pcap-proven), extension
  headers, fragmentation, DHCPv6, a resolver; and beyond any RFC's scope yet: reassembly and
  congestion control
- ✅ **Telemetry plane** — [RFC 0026](rfc/0026-telemetry-plane.md), accepted 2026-08-17,
  drafted and implemented the same day. [ai-native.md](ai-native.md) §2 as written: a 64-byte
  typed event, schema-versioned and never text; one lock-free drop-newest ring per CPU; a
  registry hash a stale tool refuses rather than misreads; producers at every kernel crossing
  (dispatch, syscall exit, rendezvous, signal); and `bin/traced`, the developer tracing tool,
  holding the rings read-only and the tails read-write, draining on an armed deadline for the
  life of the boot. Two boot gates on every placement, one negative-armed. **Not done, by
  stated decision:** per-domain enable bits (deferred to their first consumer), the `Audit`
  class's backpressure ring (reserved and refused until the audit RFC), a flight-recorder
  mode (one header bit, wanted by the next hang hunt), and the deliver-to-seen hop of the
  retired pipeline stamps, which no kernel crossing can see
- ✅ **`bhaskixboot.efi`** — our own UEFI loader, replacing Limine behind the same `Handoff` (the
  sovereignty milestone the boot shim was designed to enable). [RFC 0028](rfc/0028-bhaskixboot.md),
  steps 1–7 implemented, closed 2026-08-18: hand-rolled firmware bindings, byte-proven payload,
  a drawn KASLR slide the kernel confirms, four CPUs the kernel starts itself (MADT discovery,
  kernel-side INIT-SIPI), and **the full Limine-lane gate set answered natively** — **107
  passing assertions on both loaders as measured 2026-08-24**
  (`tests/qemu/boot-test.sh native | sed 's/\x1b\[[0-9;]*m//g' | grep -c '^ok '`), plus the
  loader-specific lane's own set and its permanent negative arm. *This line said "74 gates",
  a hand-maintained tally that nothing in the tree produces; see TRACKER's changelog for
  2026-08-24. The claim it carries — parity between the two loaders — is unchanged and is now
  checkable by running each lane and comparing.*
  Limine remains as the second lane, exactly as the RFC keeps it
- ✅ **Package management and image building** — [RFC 0030](rfc/0030-packages.md), accepted
  2026-08-19, all six steps. A package is a program plus the
  authority it asks for, in one reviewable file: the boot image is a deterministic
  function of `packages/*.manifest.in` (assembled twice and byte-compared every build,
  the fourteen boot programs' authority written down and shipped), and `pkg
  install/list/run/remove` work at the shell — verified in ring 3 by the same
  zero-`unsafe` parser the host tools use, crash-safe ordering proven by what a
  reinstall does not hit, over-asking manifests refused whole before a domain exists,
  every operation priced through the journal. The kernel gained no method and no object.
  Refused with written triggers: network fetch, signatures, dependency resolution,
  upgrades; install-time scripts refused flat — a postinst is ambient authority
- ⬜ **libc** — resolved into the **Linux personality** ([RFC 0005](rfc/0005-linux-abi-compatibility.md),
  revised for implementation 2026-08-19), exactly as that RFC's impact table asked: the
  bullet conflated source compatibility with binary compatibility, and the native half
  is a refusal already made — RFC 0008's ABI *is* the capability interface, a native
  program links no libc at all, and the user-mode shell is the standing demonstration.
  What remains is the binary half: the Linux `x86_64` ABI as a personality in a service
  domain — statically linked Go first, tiers defined by traced workloads, `-ENOSYS`
  through the telemetry plane, and the three rules that keep the nucleus free of
  Linux-shaped concepts. **Steps 2–8 are implemented and the service domain now exists**:
  the translation ran in the nucleus until 2026-08-20, which
  [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md) records with its correction trigger
  and [security.md](security.md) §1's T11 priced; [RFC 0032](rfc/0032-a-supervisor-interface.md)
  moved it out in ten steps and the nucleus now interprets **no** Linux syscall number, gated on
  every boot; [RFC 0033](rfc/0033-what-a-hosted-process-is.md), accepted the same day, then said what
  a hosted process *is* — a record in that service bound one-to-one to a domain — which closes
  architecture question **A6** and unblocks L1 below. **Tier 1 landed 2026-08-23** (step 8): a hosted
  program opens the directory it was given, lists it, rewinds the listing with `lseek`, `fstat`s
  it, reopens through it and reads a second file; asks `uname`; and finds through a two-request
  `ioctl` allow-list that its console is a terminal and its file is not — with the mandatory fuzz
  target at 22.4M executions. `readlinkat` and `/proc/self/exe` are left open on purpose: a hosted
  process need not have an image path, and inventing one would be the first thing this adapter made
  up. The step found three nucleus bugs on the way, all fixed, one of which meant a hosted program
  could `read` exactly once per boot ([RFC 0044](rfc/0044-revocation-that-reaches-the-mapping.md),
  and [security.md](security.md) §2's note on immediate transitive revocation). RFC 0031 is also where this bullet's
  *destination* is written down — the L1–L4
  application milestones below, and the containment they must inherit, all four still unmet

**Exit:** Bhaskix self-hosts its own userspace utilities, does useful network I/O, and boots on its
own bootloader.

---

## Phase 3 — Enterprise Features

**Ordered, as of 2026-08-20, and this list was unordered until then.** The rows that fund
[security.md](security.md) §1's *unmet* threat rows come first. The precedent is this project's
own: part of the IOMMU moved out of this phase and into Phase 2 when
[RFC 0012](rfc/0012-iommu.md) was accepted, because leaving it here left T3 and T4 unfunded for
the length of Phase 2 — **a mitigation that arrives after the thing it protects has shipped was
never funded, it was only listed.**

The order is still by **dependency**, as line 3 of this file requires, and not by fear: each
security row below names the prerequisite that actually gates it, and two of them are gated on
things this project has not decided rather than on work it has not done. Nothing moved into
Phase 2 — see [security.md](security.md) §1's gap list for why the ranking there is by *attacker
cost* and is not a schedule.

- **Secure boot chain** — Secure Boot, TPM measurement, sealed keys. **First, and the whole of
  [security.md](security.md) §1's top-ranked gap**: the kernel image is loaded today with no
  authenticity check at all, so whoever can write the ESP owns ring 0 from the next boot. Three
  prerequisites, none of them optional and one of them not a task: the **TPM 2.0 driver**, which
  is item 12 of [driver-model.md](driver-model.md)'s own Phase 3 list; a **`HANDOFF_VERSION` bump**,
  because the TPM event log has no path into the kernel and carrying one means a new handoff field;
  and **key custody, which is an open governance question** ([GOVERNANCE.md](../GOVERNANCE.md), and
  `security.md` §10). [RFC 0030](rfc/0030-packages.md) already refused package signatures for
  exactly that reason — *a signature without key storage, distribution or revocation is theatre
  that trains reviewers to see green checkmarks* — and signing a kernel while the key story is open
  would reproduce that refusal one layer down. The trigger is
  [RFC 0028](rfc/0028-bhaskixboot.md)'s and it is already written: physical hardware, M1-17
- **Secure update** — immutable root, A/B slots, rollback protection. Second because it needs the
  same key infrastructure the row above builds, and because RFC 0030's deferred package signatures
  are discharged here rather than separately. `security.md` §7 is its specification, written in
  advance
- **Audit framework** — hash-chained log over the telemetry plane, remote attestation. Third
  because the plane it consumes **already exists** ([RFC 0026](rfc/0026-telemetry-plane.md),
  Phase 2), which makes this the cheapest of the three to start and the one that moves T8 off
  *partial*. What is owed is precise: the `Audit` class is **reserved and refused** today —
  emitting it is counted and dropped — and this row is the backpressure ring, the hash chain, and
  audit-grade naming
- **Hosted-process address-space randomisation** — **before the L1 row below, and that is the
  point.** Bhaskix's own services are Rust; the software L1–L4 brings is C, and a hosted process at
  a fixed image base with a fixed stack turns any bug in BusyBox or `curl` into a reliable exploit.
  The domain still contains it — containment is the claim being sold, and cheap exploitation of the
  contained thing weakens it. **Scoped to the adapter**: this is `bin/linuxd`'s mapping policy, not
  a kernel change. It does **not** touch Bhaskix's own programs, whose per-program fixed bases are
  a deliberate decision taken on 2026-08-13 — they were all at one address, which made a debugger
  useless — and are asserted by boot gates. Note also that the ELF loader refuses `ET_DYN` for ring
  3 on purpose, to keep relocation processing out of the program loader; native ASLR would reopen
  that and is a separate decision needing an RFC
- **Linux compatibility L1** — see the section below. It sits here because a container runtime that
  cannot run BusyBox is a container runtime for nothing. It is also what makes `bin/linuxd` the
  largest concentration of authority in the system — supervisor handles, a directory capability and
  every hosted process's descriptors — so the thing to watch as this row proceeds is its
  **`unsafe` budget**, which the build already enforces per crate, and the authority list in
  `security.md` §1's T11 note, which every step that adds to it must extend
- **Container runtime** — container domains, OCI image support
- **Virtual machines** — VMX/SVM, EPT/NPT, vCPU threads, virtio device backends
  (the domain abstraction from M5 is what makes this additive rather than a second kernel)
- **Storage** — volume management, snapshots, encryption at rest
- **RBAC** — `bhaskixd-authz` over capabilities
- **IOMMU, the rest of it** — nested translation for VMs, and AMD-Vi. Interrupt remapping landed in
  Phase 2 instead, and is on by default.
  Discovery, per-device domains and strict mapping moved to Phase 2 when
  [RFC 0012](rfc/0012-iommu.md) was accepted: they are what make a driver's mistakes
  containable, and leaving them here left `security.md` §1 T3 and T4 unfunded for the
  length of Phase 2
- **Side-channel mitigations** — the documented Phase-1/2 gap in [security.md](security.md) §1.
  **Last, deliberately.** It is the only row here whose threat is *out of scope* in the threat
  model rather than unmet within it, the mitigations are per-CPU-generation work this project
  cannot yet sustain, and two of the mechanisms — KPTI-style isolation and core scheduling — are
  still open questions in `security.md` §10 rather than decided work

**Exit:** a signed, attestable Bhaskix boots, runs containers and VMs side by side under one
scheduler, updates atomically, and survives an external security review of the stated threat model.

---

## Linux compatibility — L1 to L4

**A goal, and every row below is unmet.** Bhaskix aims to run the Linux software ecosystem through
an adapter above its own services — *not* by reproducing Linux kernel architecture inside itself,
and not by running a Linux kernel underneath. [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md)
is the architecture; [RFC 0005](rfc/0005-linux-abi-compatibility.md) is the translation.

The letters exist to avoid a collision: RFC 0005 already uses **Tier** for *system-call* tiers
defined by tracing a binary. **L** rows are *applications*.

**L1 is the first row whose prerequisite is a decision rather than code.** Every call it names —
`execve`, `wait4`, `pipe2`, `openat`, `/proc/self/*` — means something different depending on
whether a Linux process is a Bhaskix domain or a share of one, and on where its descriptor table
lives. That is [RFC 0033](rfc/0033-what-a-hosted-process-is.md), and it is **settled — accepted
2026-08-20**, all ten steps built and gated: a Linux process is a record in `bin/linuxd` bound
one-to-one to a domain, its pid invented in ring 3 and surviving an `execve`, its descriptors
capabilities the adapter holds. The row below can start, and what it is still missing is now a list
of named calls rather than an undecided shape.

| | Target | What it demands beyond the row above | Status |
|---|---|---|---|
| **L1** | Static ELF binaries, BusyBox, shell utilities, `curl`, OpenSSH | Its prerequisite is **met**: [RFC 0033](rfc/0033-what-a-hosted-process-is.md), accepted 2026-08-20, gave it a process record, a pid that survives an `execve`, a descriptor table held by the adapter, real `openat`/`read`/`close`/`dup`, `pipe2` with a reader that parks, `fork`, `wait4` and `/proc/self/{status,maps}`. What is left is **breadth, not shape**: terminal `ioctl`s, `getdents`, `stat`, a writable path, argv and environment through `execve`, and the signal gaps a shell notices | 🔨 **started 2026-08-20; BusyBox runs as of 2026-08-27** — `bin/busybox`, a static BusyBox 1.30.1 nobody here wrote or built, loads through this kernel's own ELF loader into a Linux-tagged domain and prints `hello from busybox` from its `echo` applet in sixteen calls. Ten syscalls were added to reach it, measured from the machine's own trace rather than guessed: `stat`, `lstat`, `getuid`, `geteuid`, `getppid`, `prctl`, `access`, `writev`, `tgkill` and `brk` — plus region splitting in the VM, without which glibc's static-PIE relocation could not re-protect its RELRO. Its **shell** runs too: `sh -c 'echo hi from sh'` prints in twenty-nine calls, gated and watched red. **What that is not**: an *interactive* shell — `sh` reaches a correct `/ #` prompt and cannot read a key, because the adapter holds the console `WRITE`-only on purpose so it cannot take a byte typed at the Bhaskix shell. Input for a hosted process is a decision about authority, not a missing syscall. Also no filesystem breadth, and `readlink("/proc/self/exe")` still refused. A static Go binary also loads, runs and traces its calls, and seven hosted probes exercise the process surface |
| **L2** | Python, GCC, Clang, Rust, Go toolchains | The dynamic linker and a real libc's expectations, process groups, filesystem breadth — and **a forked child's full register file**, which RFC 0033 left open on purpose: today a child gets `rax`, `rsp` and `rip`, and the rest needs the syscall entry stub widened on the hottest path in the system, measured before and after | ⬜ not started |
| **L3** | nginx, Apache, PostgreSQL, MariaDB | Tier 2 sockets and `epoll`, `mmap`-heavy storage, `fsync` durability, users and permissions | ⬜ not started |
| **L4** | Larger server software, container workloads | Resource control mapped onto `ResourceEnvelope`, image formats, orchestration | ⬜ not started |

The demonstration these build toward: **Bhaskix boots → a compatibility domain → nginx + MariaDB +
OpenSSH → network clients connect**, with no Linux kernel underneath. Until a gate proves a row, no
document, release note or README may state or imply that it works — the same rule every other
claim in this project lives under.

**And the compatibility path inherits the containment or it is not worth having.** The security
tests that say so — a hosted application attempting escape, a hostile driver, Linux `root` confined
to its domain, revocation reaching every descriptor derived from a revoked capability — are
specified in RFC 0031 §6 and become permanent boot gates as each is written.

---

## Phase 4 — AI-Native Platform

Depends on the telemetry plane (Phase 2) and the policy hooks, which are added alongside their
subsystems throughout Phase 1–3 rather than retrofitted.

- `bhaskixd-ai` domain, model loading, NPU/GPU access via ordinary device capabilities
- Runtime-prediction model behind `SchedPolicy`
- Reclaim, prefetch, and I/O policy models
- Streaming anomaly detection → incident alerts
- Diagnostics: causal correlation over telemetry
- Local assistant (LLM in a capability-scoped domain)
- Bounded autonomous actions with operator-authored limits

**Exit:** measurable improvement on at least one published benchmark against the default heuristics —
**and** the degradation test passes: kill `bhaskixd-ai` mid-benchmark and the suite still completes
correctly at baseline performance.

That second criterion is the important one. A system that gets faster with AI and breaks without it
has made AI a dependency, which is exactly what [ai-native.md](ai-native.md) §0 forbids.

---

## Phase 5 — Enterprise Ecosystem

Editions are configurations of one kernel and one service set, not forks.

| Edition | Distinguishing content |
|---|---|
| **Server** | Headless, networking, containers, remote management |
| **Hypervisor** | Minimal host surface, VM domains, live migration |
| **Edge** | Small footprint, tickless, offline AI, field update |
| **Embedded** | AArch64, RT class, deterministic latency, no dynamic allocation in critical paths |
| **Desktop** | GPU (`domain` placement), compositor, audio, USB |

Desktop is deliberately last. It is the largest driver surface and the least differentiating work,
and doing it early would consume the project.

---

## First release — 29 November 2026

**Set by the project lead on 2026-08-19.** The first public release of Bhaskix, from a machine that
today boots on its own loader, runs services in isolated domains, speaks IPv4 and IPv6, installs
packages onto a journalled filesystem, and loads a real Linux binary.

### What the release is

A **developer preview**: an ISO a stranger can boot in QEMU, plus the source, the RFC record, and
the honest gap list. Not a product, not an installer for a daily machine, and not a claim of
production readiness. The word for what this is, and the word the release notes will use, is
*preview*.

### Release criteria — all verifiable by running a command

| | Criterion | Where it stands on 2026-08-19 |
|---|---|---|
| R1 | `make test` green on every placement and lane, from a clean clone | met, and kept green commit by commit |
| R2 | The ISO boots to a user-mode shell on BIOS, UEFI, and our own loader | met |
| R3 | A package installs, runs with manifest-derived grants, and removes | met (RFC 0030) |
| R4 | Networking answers on both address families, measured | met (RFC 0018–0029) |
| R5 | **Boots on one piece of real hardware** | ✅ **met 2026-08-23** — the report was read off a Lenovo SR550, and its RT wake latency (worst 1.532 µs against a 50 µs target) is the first hardware measurement this project has. One machine of one model, and nothing has run on it longer than a boot |
| R6 | The design documents reviewed by two people who did not write them | **not met** — Phase 0's own criterion |
| R7 | A release note that states the gaps above as plainly as the features | **drafted 2026-08-30** — [release-notes.md](release-notes.md). Every figure in it is dated and must be re-measured on the day |

**R5 and R6 are the two that decide what the release can say.** If they are still unmet on the day,
the release ships and says so — a preview that boots only under emulation, reviewed by one person,
is a truthful thing to publish and a dishonest thing to dress up.

### What is explicitly *not* in the first release

A libc, self-hosting, a package repository, signatures, containers, VMs, a desktop, or a promise of
ABI stability. **The signatures are the notable one**: the preview ships with a kernel the loader
does not authenticate, which is [security.md](security.md) §1's top-ranked gap, deferred here for
reasons that are written down rather than forgotten — it needs a TPM driver, a handoff change and a
key-custody decision the project has not made. The release note says this in its own words; a
preview that a stranger boots in QEMU is the one setting where the omission costs least, and that
is an argument for shipping it stated plainly, not for leaving it unsaid.

The Linux personality ships as far as it has got — which by the release will be
further than it is today — described by what it runs, not by what it aspires to. **No L row is in
this release**, and the release note says so in those words rather than describing the goal in a
tense that could be mistaken for a state.

---

## The book

***Mastering Bhaskix*** is scoped in
[ebook-mastering-bhaskix.md](ebook-mastering-bhaskix.md) and written in
[`book/`](../book/): four parts, thirty-six chapters, four interludes and a
closing chapter, each carrying the evidence in this tree that makes its claim
checkable.

**It is deliberately not a milestone.** The book tracks the repository rather
than the other way round, and scheduling it would invert that — a chapter due on
a date is a chapter that gets written before its evidence exists, which is the
one failure the scope document says would make the book worthless.

What it does have is a **trigger**: thirty-five of the thirty-six chapters are
writable today, and the one that is not (*The keystroke*) is waiting on RFC 0041
step 7. The first edition's own open question — whether to ship stating USB and
real hardware as gaps, or to wait — is question 4 of that document and is not
settled here.

## How to pick up work

1. Read [vision.md](vision.md), [architecture.md](architecture.md), and
   [coding-style.md](coding-style.md).
2. Look at the current milestone above. Work outside it is welcome as an RFC, but reviewer attention
   goes to the current milestone first.
3. For anything substantial, open an RFC in `docs/rfc/` before writing code. This is not
   bureaucracy — it is the single practice that most distinguishes kernel projects that survive from
   those that do not.
4. Issues labelled `good-first-issue` are real and are kept stocked. If they run dry, that is a
   maintainer failure; say so.
