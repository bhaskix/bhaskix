# Bhaskix — Security Architecture

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md).*

"Security by design, not by addition" is the second core principle in [vision.md](vision.md). This
document says what that means mechanically, what we defend against, and — equally important — what
we do **not** defend against. A threat model that claims to cover everything covers nothing.

---

## 1. Threat model

> ### Before any row below: what this evidence is worth
>
> **Nothing in this document has ever been observed on physical hardware** (M1-17). Every mitigation
> marked built below is built and gated *in QEMU*, and QEMU is not a machine: its VT-d is a model of
> an IOMMU, it has no SMM, no Management Engine, no firmware with its own opinions, and no device
> that misbehaves in the way real devices do. That is not a reason to distrust the rows — the gates
> are real and have each been watched go red — but it is a ceiling on how far any of them should be
> believed, and it applies to all of them at once.
>
> The second ceiling is narrower and sharper: **the kernel image is loaded without any authenticity
> check.** `bhaskixboot.efi` refuses a kernel that fails the *ELF parser* — the negative arm in
> `tests/qemu/native-boot-test.sh` corrupts the magic and asserts the refusal — and that is
> integrity against corruption, not authenticity against an attacker. Anyone who can write the ESP
> replaces the kernel and owns ring 0 from the next boot. T6 and T7 below are that gap, and their
> status column now says so.
>
> **The status column is new, 2026-08-20, and it exists because of a sentence already in this
> document**: *a mitigation column is a claim, and a claim whose limits are not written down is
> believed further than it should be.* **Three rows described mitigations that do not exist** (T5,
> T6, T7) **and a fourth described one that is half-built** (T8), all in the present tense, and a
> reader could not tell which. That is the failure mode this project exists to refuse, found in the
> project's own security document.

### In scope — we intend to defend against these

**Status** is what is true in the tree today, not what the design intends: **built** means
implemented and held by a gate that has been watched fail; **partial** means some of the mitigation
exists and the row says which part; **planned** means the mitigation column describes a design and
nothing in the tree implements it yet.

| # | Threat | Primary mitigation | Status |
|---|---|---|---|
| T1 | A compromised userspace process attempts to gain kernel privilege | Capability system; no ambient authority; no setuid; W^X; SMEP/SMAP | ✅ **built** — capability system, no ambient authority, SMEP/SMAP and the exception table gated on every boot. **One weakness named**: there is no ASLR for user programs; only the kernel image is slid |
| T2 | A compromised process attempts to access another domain's data | Address-space isolation; capabilities; no shared namespace by default | ✅ **built** — address-space isolation and immediate transitive revocation, both gated. A hole was found and closed on 2026-08-23, within the day: revocation reached capabilities and not the **memory mappings** they named, so a borrower went on reading a frame its lender had taken back and reused ([RFC 0044](rfc/0044-revocation-that-reaches-the-mapping.md), §2 rule 3's note). This cell read ✅ throughout the period the hole existed, which is the ordinary way of such things and the reason the note under rule 3 is kept rather than deleted |
| T3 | A compromised or malicious **device driver** | IOMMU-enforced DMA windows; per-device capabilities; relocatable-service isolation | ✅ **built**, under the three conditions the note below states — and on a machine with no IOMMU a domain-hosted driver is refused outright rather than run unprotected |
| T4 | A malicious peripheral performing DMA (evil maid, malicious PCIe/Thunderbolt device) | IOMMU on by default; devices default-denied until enumerated and granted | ✅ **built**, same three conditions; interrupt remapping is on by default and gated |
| T5 | A guest VM escaping to the host | Domain isolation is the same mechanism as containers; EPT/NPT; no shared hypervisor codebase to diverge | ⬜ **planned** — domains exist and are the mechanism; **VMX/SVM and EPT/NPT do not**. There are no guests yet, so nothing has escaped and nothing has been prevented. Phase 3 |
| T6 | Persistence across reboot (bootkit, tampered kernel or initrd) | UEFI Secure Boot chain; measured boot into TPM PCRs; signed, immutable system image | ⬜ **planned, not built** — no Secure Boot chain, no TPM measurement, no signed image. The loader refuses a kernel that fails the ELF *parser*, which is corruption-detection, not authenticity. **Whoever can write the ESP owns ring 0.** Phase 3 |
| T7 | Tampering with an update in transit or at rest | Signed A/B images; rollback protection via monotonic counter; verified before switch | ⬜ **planned, not built** — no signing, no A/B slots, no rollback counter. There is no update mechanism at all yet, which is why nothing has been tampered with. Specified in §7; Phase 3 |
| T8 | Undetected compromise | Tamper-evident audit log; remote attestation; the telemetry plane is the audit source | 🔨 **partial** — the telemetry plane is built ([RFC 0026](rfc/0026-telemetry-plane.md)); the `Audit` class in it is **reserved and refused**, not served — emitting it is counted and dropped, because a best-effort audit event is false assurance with a checksum (§8). The backpressure ring, the hash chain, and remote attestation are a future RFC and are Phase 3. **This cell claimed backpressure when it was first written, on 2026-08-20, and §8 four sections below already said otherwise** — an error introduced by the same edit that added this column to stop exactly that |
| T9 | Memory-safety bugs in kernel code | Rust; `unsafe` budget tracked per crate; every `unsafe` block justified and reviewed | 🔨 **partial, and permanently so** — Rust, `forbid(unsafe_op_in_unsafe_fn)`, `deny(undocumented_unsafe_blocks)`, and a per-crate budget enforced by the build. **4,465 lines of `unsafe` in tree, 3,108 of them (70%) linked into the kernel binary** — `tools/check-unsafe-budget.py --share`, which derives the ring 0 set from `cargo tree` rather than a list somebody maintains. This cell read *"4,170 lines … 2,740 of them (66%) in ring 0"* until 2026-08-26, hand-computed once with an unstated set of crates and stale by then; a figure in a security document that nobody can reproduce is the same defect as a claim nobody checks. The discipline is built; the exposure is structural and does not go to zero |
| T10 | Resource exhaustion by one domain denying service to others | `ResourceEnvelope` enforced at allocation and scheduling time, not by best effort | 🔨 **partial, corrected 2026-08-26 — this cell read ✅ built.** The **CPU** half is built and genuinely gated: shares are divided by thread count, every thread is reweighted when one is added, and the gate puts one thread and three threads on the same CPU and checks the shares hold. The **memory** half is not. `domain::charge_frames` refuses past the cap, and its only real caller is `shared::create` — so the envelope bounds **shared objects** and not a domain's own address space: `map_anonymous` charges nothing and the fault path that commits a lazy reservation charges nothing. **A domain can exhaust memory past its envelope, which is this threat.** The gate that read as proof calls `charge_frames` directly, so it tests the accounting function rather than the property; see the note below |
| T11 | A hostile or compromised **Linux application inside a compatibility domain**, attacking through malformed system-call arguments or through Linux privilege (`root`) | The Linux personality translates and never manufactures authority; a hosted process holds no capabilities and has no way to name one; a compatibility domain reaches only what it was granted; and **the translator itself runs in a service domain** as of 2026-08-20 — the nucleus interprets no Linux syscall number, gated on every boot ([RFC 0005](rfc/0005-linux-abi-compatibility.md), [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md), [RFC 0032](rfc/0032-a-supervisor-interface.md)) | 🔨 **mitigated 2026-08-20, and the price rose 2026-08-23**, with it written out in the note below rather than rounded to "contained" — the translator is in ring 3 and the nucleus interprets **0** Linux syscall numbers, gated; what a compromise of the adapter still reaches is enumerated, and it now includes **the network** |
| T12 | **A remote peer denying service to a listening port**, without authority, credential, or any address that must exist beyond completing a handshake | A connection that completes a handshake but reaches no application has **no local user**, so the service is its local user and discharges the obligation `CLOSE-WAIT` names on one (RFC 9293 §3.3.2) — [RFC 0061](rfc/0061-a-connection-nobody-accepted.md). A counter reaches the boot report and reads zero on a healthy boot | 🔨 **mitigated 2026-08-31, and it was open from the day `bin/tcpd` first listened.** One `SYN`, one `ACK`, one `FIN` disabled a listening port until reboot: the connection parked in `CLOSE-WAIT`, which is neither `Closed`/`TimeWait` (so the single accepted slot was never released) nor `Established` (so `ACCEPT` answered `LATER` for ever), and nothing could move it because leaving that state needs a `CLOSE` from a local user that never existed. **Found by hunting a flaky test, not by review** — it had been reddening CI intermittently since 2026-08-24 and was filed three times as environmental, timing-bound, and then as a harness defect. [RFC 0048](rfc/0048-a-listener-that-cannot-be-wedged.md) is titled *a listener that cannot be wedged*; it priced the half-open wedge and left this one standing, so the title was true of the attack it studied and too broad as a conclusion. **What is fixed is the reclaim; the listener serves one connection at a time and that is now a decision rather than a limit.** RFC 0061 step 2 (a backlog) was **withdrawn 2026-08-31 on evidence**: RFC 0048's cookies stay valid 64–128 s, so a peer whose `ACK` lands while the slot is busy retransmits and is built the moment it frees — measured at **11 connections through the one slot in a single boot**, 9 reclaimed, the real caller still served. A backlog would buy latency alone and pay for it by holding state for peers no application has accepted, which is exactly what RFC 0048 removed. A peer that completes a handshake and *stays* does still occupy the slot until the application takes it, which is a capacity limit costing an attacker a real connection — not a wedge |

**A note on T10's gate, because it is the more useful half of that correction.** The boot gate
behind T10 asserts a line the kernel prints after calling `domain::charge_frames` **directly**: it
charges eight frames against a cap of eight, charges a ninth, and requires the refusal. That is a
true and worthwhile test of the accounting function. It is not a test of the claim above it, which
is that a domain's *allocations* are charged — and nothing in the tree connected the two, so the
gate went green for a year while the property it was written to defend was false for every
allocation path except one. **A gate that exercises the mechanism rather than the property will pass
while the property is absent**, and this one names the difference now.

### Out of scope — stated honestly

We will not pretend to cover these. Each has a note on whether it becomes in-scope later.

| Threat | Why out of scope | Future |
|---|---|---|
| Physical attacker with unlimited time and equipment (bus probing, chip decapping, cold boot) | No software-only mitigation is credible | Memory encryption (SME/TME) — Phase 3, mitigation not solution |
| Compromised firmware / SMM / Management Engine | Below our privilege level, by construction | Attestation *detects* some cases; it cannot prevent them |
| Microarchitectural side channels (Spectre-class, MDS, port contention) | Requires per-CPU-generation mitigation work we cannot sustain yet | Phase 3: core scheduling, IBRS/STIBP, cache partitioning. Documented gap until then. |
| Supply-chain compromise of the Rust **toolchain** | Real, and not solved by us | Reproducible builds, and the boot image is already a deterministic function of its package set, byte-compared twice per build ([RFC 0030](rfc/0030-packages.md)) |
| ~~Supply-chain compromise of crates.io dependencies~~ | **Corrected 2026-08-20: the shipped workspace has none.** `Cargo.lock` holds twenty packages and every one is `bhaskix-*`. This row previously promised "vendored + hash-pinned dependencies" as Phase 2 future work, which under-claimed what was already true — **there is nothing to vendor**, and an unearned understatement is as wrong as an unearned claim | Held by a gate, not by habit: `tools/check-deps.py`, run by `make gates` in CI, reads every manifest and rejects any external crate not in its `ALLOWED_EXTERNAL` set. That set holds exactly one name — `libfuzzer-sys`, reached only by `fuzz/`, **which is its own workspace on purpose and is never shipped** (its lockfile pulls ten transitive crates; none of them reach a booting machine) |
| Denial of service by an authorised administrator | Authorisation is the boundary; we do not defend against correctly-authorised destruction | Audit log makes it *attributable*, not impossible |
| ~~**Denial of service against a TCP listener by an unauthenticated peer**~~ **— CLOSED 2026-08-26 by SYN cookies ([RFC 0048](rfc/0048-a-listener-that-cannot-be-wedged.md) steps 3–4).** `bin/tcpd` now allocates **nothing** on a `SYN`: the initial sequence number is a keyed hash over the four-tuple, and the accepted slot is taken only when an `ACK` carries that cookie back and verifies. A peer that sends a `SYN` and vanishes costs this stack one reply and no state, so there is no half-open connection to hold and the deviation from RFC 1122 §4.2.3.5 stops mattering — with no half-open connection, there is nothing for `R2` to govern. Gated on every networked boot: `tcpd cookies  N connection(s) built from a verified SYN cookie`, watched red. **What remains true:** the accepted slot is still *one*, so a peer that completes a handshake and holds it excludes others — that is a capacity limit, not a wedge, and it costs an attacker a real connection rather than one packet. The history below is kept because how this was found and priced is the useful part. ~~**In scope, and currently open — this row is a gap, not a refusal (found 2026-08-24).**~~ `bin/tcpd` has one accepted slot; a `SYN` whose peer never completes the handshake held it for **242 seconds**, and every later `SYN` was refused silently. One packet, from an address that need not exist, no capability and no handshake. Narrowed to **14 seconds** the same day by [RFC 0048](rfc/0048-a-listener-that-cannot-be-wedged.md) step 1 — a reduction, **not a fix**: a peer sending one `SYN` every fourteen seconds still owns the slot. **And that narrowing is a deliberate deviation from a MUST, recorded rather than hidden.** RFC 1122 §4.2.3.5: *"R2 for a SYN segment MUST be set large enough to provide retransmission of the segment for at least 3 minutes."* The specification was read on 2026-08-24; 14 seconds is not 180. Availability was chosen over the letter, knowingly, because the compliant value is precisely what let one packet deny service | ~~SYN cookies (that RFC's steps 2–4)~~ — **done 2026-08-26.** What is left is the single accepted slot, which bounds *concurrency* rather than exposing a wedge, and a rate limit for the reply itself if this service ever faces more than the boot harness |
| Traffic analysis, timing, and power side channels on network paths | Out of scope for an OS kernel | — |
| Learning which TCP ports are open by probing them | **In scope as a deliberate disclosure, since [RFC 0047](rfc/0047-refusing-a-connection-to-a-port-nobody-holds.md), 2026-08-24.** `bin/tcpd` answers a `SYN` for a port no listener holds with a `RST`, so a peer learns *shut* rather than inferring it from silence. It learned the same fact before, more slowly; what changed is the speed, equally for a scanner and for every legitimate client. A stack that stays silent instead makes its own clients unable to tell shut from lost, which is the worse property — and every peer this machine will meet behaves this way | A rate limit, when this service faces anything that is not the boot harness — a reset is a reply an unauthenticated peer can ask for. Written as a trigger in that RFC's open question 2 |

> **T3 and T4 are delivered as of 2026-08-11, on a machine that has an IOMMU.**
> [RFC 0012](rfc/0012-iommu.md) was accepted on 2026-08-04 and all seven of its steps are
> implemented. Every device the kernel drives translates through **its own** page table under its own
> domain id, a device reaches only the frames it was given, revoking a mapping is enforced against
> the hardware, and interrupt remapping is **on by default** — so a device cannot raise an interrupt
> it was never programmed to raise, which is what retires [RFC 0011](rfc/0011-irq-handler.md)'s
> residual risk.
>
> **That last sentence is true of one remapping unit, and a platform may have several.**
> Corrected 2026-08-25 on accepting [RFC 0049](rfc/0049-every-unit-the-firmware-named.md), which
> made translation reach every unit the firmware names and **deliberately left interrupt remapping
> where it was**: `enable_interrupt_remapping` programs the first programmed unit and no other. On
> the SR550 — four units — that means devices governed by the other three can raise interrupts this
> kernel never issued them, so RFC 0011's residual risk is retired **for the devices under unit
> zero and for no others**. It is a smaller claim than the paragraph above made for three weeks,
> and it is smaller than the fix that shipped beside it: translation was widened to every unit
> because there was evidence forcing it, and remapping was not, because there was none. Widening it
> needs a machine that routes an interrupt through a unit this kernel does not program, and that
> measurement has not been made.
>
> The boot says which world the machine is in:
>
> ```
>     iommu window   00:03.0 39-bit, 3 levels, 0 reserved pages mapped, 0 refused
>     iommu irq      remapping interrupts; compatibility format blocked, every message is a handle
>                    this kernel issued
> ```
>
> **Three conditions, and a reader should know all of them.** On a machine with **no** IOMMU nothing
> above is true and the boot says so, in the words this note used to quote — a domain-hosted driver
> is refused outright, because a domain that could aim a device with physical addresses could aim it
> at the kernel. `iommu=off` produces the same state deliberately, for a machine where the unit is
> what is wrong. And **nothing has ever booted on physical hardware** (M1-17), so every word here is
> QEMU — real firmware declares reserved regions that QEMU never has, and that path has host tests
> and no more.
>
> Gated either way: a boot test asserts interrupts *are* remapped, so a machine that quietly fell
> back to the old risk is a red build rather than a table that became true-looking.
>
> This note said it would come out when the code landed. It is kept, rewritten, because the useful
> version is not "delivered" but *under what conditions* — **a mitigation column is a claim, and a
> claim whose limits are not written down is believed further than it should be.**

> **What the adapter holds grew on 2026-08-23.** `bin/linuxd` now holds a
> capability to the protocol service and a page for datagrams, because RFC 0005
> step 9 wired `socket`, `bind`, `sendto` and `recvfrom` and a hosted program
> calling `socket()` had nothing behind it. So a compromise of the adapter now
> reaches **the network**, on top of every hosted process's files.
>
> **And it moves further from
> [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md)'s interface I5**,
> which says an adapter should host *one workload's* process group rather than
> being a system service every Linux process shares. One system-wide
> `bin/linuxd` already contradicted that; the network makes the union larger.
> The alternative was on the table — per-hosted-process authority declared in a
> manifest, which is an RFC and a supervisor change before any socket works —
> and the choice was the project lead's. It is written here rather than
> absorbed, because the whole value of I5 is that drift from it stays visible.

> **T11 is in scope and is mitigated, as of 2026-08-20 — and this note stays because how it
> got there, and what it now costs, are worth more than the tick.**
> [RFC 0005](rfc/0005-linux-abi-compatibility.md) §"Where it lives" requires the Linux personality
> to run in a **service domain**, precisely so that a bug in the largest untrusted-input parser in
> the project is a compromise of that domain and not of the kernel. On 2026-08-19 the
> implementation was in the nucleus: `kernel/src/syscall.rs` held the foreign-call path and
> eighteen interpreted Linux call numbers, and `kernel/src/signal.rs` built and restored Linux
> signal frames — on the order of 700 lines of Linux ABI in ring 0. (Past tense throughout this
> paragraph: it describes the tree on that day, and is kept because the correction is worth more
> than a tidy document.)
>
> **As of 2026-08-20 that is no longer where it lives.** `kernel/src/signal.rs` is deleted, the
> foreign-call handlers are deleted, and the count of Linux numbers the nucleus interprets —
> printed on every boot that ran a hosted program, and gated — reads **0**. `bin/linuxd` answers
> every foreign call from ring 3. Every parser, every signal frame, every `mmap` decision, every
> descriptor and the futex table itself are outside the kernel.
>
> **So both halves of the mitigation column hold.** A hosted process holds no capabilities and
> cannot name one, and its domain reaches only what it was granted — structural, and unchanged. A
> bug in the *translator* is now a bug in a ring 3 program that holds: one endpoint, three pages,
> a **write-only** console capability (it can print; it cannot read what somebody typed at the
> shell), sixteen notifications it may signal and may not wait on, and a supervisor handle to each
> domain it hosts. That is authority over hosted processes and over nothing else.
>
> **And, since [RFC 0053](rfc/0053-input-a-domain-was-given.md) on 2026-08-27, the console input of
> a domain that was granted it.** The console capability above is still write-only and that sentence
> is still true; what changed is that a *domain* can be granted input, and the adapter holds a
> handle to each domain it hosts. So a compromised adapter can take keystrokes **while a granted
> domain is running, and for no other domain** — the check is in the nucleus and it cannot lift it,
> the grant is one domain at a time, and it is released when that domain ends. That bound is why
> this shape was chosen over giving the adapter console `READ`, which would have reached every
> keystroke for ever.
>
> **[RFC 0054](rfc/0054-a-hosted-read-that-waits.md) added waiting, on 2026-08-28, and one
> capability with it**: `READ` on the console's own notification, so the adapter can park a hosted
> thread until a key arrives. It confers waiting and **not reading** — `READ` where the futex pool
> is `WRITE`, so the adapter cannot signal it and cannot invent a keystroke, and taking the byte is
> still the grant-checked call above. It also *closes* a denial of service rather than opening one:
> that notification takes one waiter, so an adapter free to park anything on it could hold the
> console's only waiter slot and the Bhaskix shell would never wake for a keypress. The nucleus
> refuses the park unless the calling domain holds the input grant, on the same terms as the read,
> and counts every refusal in the boot report.
>
> **[RFC 0059](rfc/0059-an-execve-that-runs-a-program.md) added one object on 2026-08-30**, and it
> is memory rather than reach: sixteen pages of the adapter's **own** memory, where a program being
> `execve`d is read in and parsed. It confers nothing over anybody else — a hosted program's bytes
> are read into it from the filesystem, checked there, and copied out into the domain that will run
> them, so no process ever holds or can write to the image it is about to become. The directory the
> exec resolves in is the one the adapter already held, and it is still `sub` rather than the root:
> a hosted `execve` can run what is inside it and can name nothing above it.
>
> "Every boot today" stopped being true on 2026-08-28: a boot with `busybox=sh` grants the console
> to the BusyBox domain, and it is the only one. Every other boot grants nothing and reaches no
> keystroke at all. It is not
> nothing — an adapter compromise is a compromise of every hosted process — and this note says so
> rather than rounding it to "contained".
>
> [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md) §5 records how the drift happened, and
> set the correction's trigger — before Tier 1's file surface, because that is when the adapter
> starts holding per-process state and moving it gets dear. The trigger was met with room to
> spare.
>
> **The mechanism was [RFC 0032](rfc/0032-a-supervisor-interface.md)**, accepted 2026-08-20: seven
> methods on a `Domain` capability and two reply shapes, so that holding a program is an authority
> a program can be *given* rather than something only the kernel can be. The trade it stated —
> **the nucleus grows a supervisor interface so the personality can leave entirely** — is now a
> measured one: the kernel's `unsafe` budget *fell* across the move, 1,514 → 1,506.
>
> **What this row does not claim:** that the adapter is correct. It claims that a bug in it is
> contained, which is a statement about placement and is now true.
>
> **And half of what that note predicted has happened, on the same day it was written.**
> [RFC 0033](rfc/0033-what-a-hosted-process-is.md) step 5 gave the adapter **`DomainControl`**, so
> that a hosted `execve` can build the domain its successor runs in — a hosted process cannot exec
> in place, because `START` refuses a domain that has threads and the thread asking is one. So the
> list above grows by one entry, and the sentence that goes with it is: **a compromised adapter can
> create domains, up to the sixteen its own envelope allows, and can do to them everything a
> supervisor can do — map their memory, write it, start threads in it.**
>
> What it still cannot do is name a capability it was not given. A domain it creates starts *empty*:
> every authority that domain will ever hold is one the adapter passes from what it already holds,
> which is one endpoint, three pages, a write-only console, sixteen notifications and a handle per
> hosted domain. There is no ambient root, no device, no memory outside its own objects.
>
> **And the other half happened too, later the same day.** RFC 0033 step 6 gave the adapter a
> **directory capability** — one directory of the filesystem, `READ` and `DERIVE` and no `WRITE` —
> so that a hosted process can open a file. So the sentence that note said would have to be written
> is written here: **a compromised adapter can read every file inside that directory, and every file
> any hosted process has open.** It cannot write one, cannot reach anything above that directory,
> and cannot name a directory it was not given — a hosted process's `/` *is* that capability, which
> is `chroot` by construction rather than by check.
>
> The list, in full, as of 2026-08-20: one endpoint, three pages, a write-only console, sixteen
> notifications, `DomainControl` within a sixteen-domain envelope, one directory, and a supervisor
> handle per hosted domain. **Every increase on that list is a decision, and each one is recorded in
> the step that made it** — which is the only way a row like this stays true.
>
> Written here rather than only in the RFC because [RFC 0005](rfc/0005-linux-abi-compatibility.md)'s
> own impact table asked for this row on the day it was drafted — *"The threat model gains an
> in-scope adversary: a hostile process inside a Linux-personality domain… This is new and must be
> written down, not assumed covered"* — and it was not written until now, while five of that RFC's
> steps shipped.

### Gaps found by the reassessment of 2026-08-20

Neither a threat nor a mitigation: **work that is missing, ranked by what it would actually cost an
attacker to exploit**, recorded here so the order survives the week it was decided in.

> **This ranking is by attacker cost. It is not a schedule, and the two orders differ on purpose.**
> [roadmap.md](roadmap.md) orders by *dependency* — it says so in its own first lines — and gap 1
> depends on a TPM driver, a `HANDOFF_VERSION` bump and a key-custody decision the project has not
> made, while gap 5 depends on nothing at all. So the roadmap's Phase 3 was reordered on 2026-08-20
> to put the rows that fund this section first *within that phase*, and **nothing was moved into
> Phase 2**; gaps 5 and 6 are merge-gate debts under §5 rather than phase items, and gaps 2 and 4
> are tracked as tasks. Reading this list as a delivery order would be reading it wrong. Each was
found by reading the tree rather than the documents, and each names what is true today.

| | Gap | Why it ranks here |
|---|---|---|
| 1 | **The kernel image has no authenticity check** | The whole of T6. It became *this project's* problem when `bhaskixboot.efi` replaced a shipped loader, and it is the only gap on this list that hands an attacker ring 0 outright |
| 2 | **`bin/linuxd` is the concentration point, and it is growing fastest** — *capped 2026-08-21* | It holds `DomainControl`, a read-only directory capability and every hosted process's descriptors, it parses attacker-controlled arguments, and its `unsafe` went **42 → 85 in one day** with L1 barely begun. This has no completion state — it is a property, not a task — so what is actionable is the number, and the number is now **capped rather than merely bounded**: `unsafe_budget_exact = true`, so the build fails if it grows *or* shrinks without somebody editing the line. **Headroom is permission nobody is using.** The audit that set it removed thirteen lines by making twenty repetitions of `&mut` to a `static mut` into eight accessors — one per table, each making the single-threaded promise once — so the cap is **72**, and both directions were watched red |
| 3 | ~~No ASLR for user programs~~ **— the hosted half done 2026-08-21** | A hosted process's `mmap` region is now **drawn per process** from `RDRAND`, 28 bits page-granular: three consecutive boots gave `0x707c9b39a000`, `0x70b501870000` and `0x70718f4f2000`. It replaced **one global bump allocator shared by every hosted process**, which was worse than fixed — each process's addresses were predictable from any other's. `fork` inherits the layout and `execve` redraws it, which is Linux's split and is host-tested. **Partial, and the split is stated**: the *image* stays where its ELF says, because the loader refuses `ET_DYN` on purpose to keep relocation processing out of the program loader — **that is [RFC 0036](rfc/0036-a-relocatable-program-in-ring-3.md), drafted 2026-08-21**, whose own first step is to seed `elf_parse` for relocations, since the audit measured that the relocation-applied path is never reached. Bhaskix's own programs keep their fixed per-program bases — a deliberate 2026-08-13 debuggability decision, and two boot gates assert those addresses. A machine with no entropy gets the floor **and the boot says so**; the gate accepts either line and refuses silence |
| 4 | ~~The kernel's user-pointer copy path has one missing invariant~~ **— done 2026-08-21** | The pass found the surface is **smaller than the bug count suggested**: only six kernel operations touch a space that is not loaded, and exactly one of them writes bytes. Everything else either writes through the CPU — where a lazily mapped page **faults** and the handler services it — or writes into a region mapped eagerly, where there is nothing to commit. The invariant now lives in `vm::frame_for_write`, which commits, beside `vm::frame_for_read`, which deliberately does not; a caller picks by saying which it is doing, and the next supervisor write gets the rule without being told. A boot gate asserts both directions, and **both were watched failing** — a write that does not commit (the original bug, put back) and a read that does |
| 5 | ~~A hostile disk image is not fuzzed~~ **— paid 2026-08-21** | `fuzz/fuzz_targets/fs_image.rs`: four arms, **123,501 executions clean**, no crash and no hang. The fourth arm exists because the first three were *measured and found not to reach the walkers* — inodes carry a checksum as well as the superblock, so a probe that panicked inside `Filesystem::list` ran **16,132 executions without ever yielding a directory entry**. Arm D re-encodes an inode after taking its fields from the fuzzer, putting attacker-chosen block pointers behind a valid checksum, which is the bug class that matters. Five paths — the walkers, `journal::home`, a directory entry, a followed block pointer, the free bitmap — are each proven reachable by a deliberate panic rather than by a coverage number |
| 6 | ~~IPv6 and NDP have the mutation harness but no coverage-guided target~~ **— paid 2026-08-21** | `fuzz/fuzz_targets/ipv6_ndp.rs`, four arms, **12,906,117 executions clean**. All five probe points reach from an **empty** corpus, including the checksum-verified echo — which settles the question this gap raised: ICMPv6's mandatory 16-bit checksum over a pseudo-header is **not** a wall to a coverage-guided fuzzer, exactly as `udp_parse` and `icmp_parse` had already shown. A repaired arm is kept anyway, because recomputing the sum is what an attacker does and the fields behind it are the ones worth attacking |
| 7 | **One entropy source, no pool** | `RDRAND` only — no `RDSEED`, no mixing, no pool. Every unpredictable number in the system, including the KASLR slide and the TCP ISN key, traces to one instruction from one vendor. The design **fails closed** where most systems fail silently, which is why this is seventh and not first |

> **Qualified 2026-08-22, and the qualification matters more than the fact.** "Zero external
> dependencies" is still true and is no longer the whole story: RFC 0038 brings **adapted
> third-party source** into `third_party/`, beginning with the xHCI register layouts taken from the
> `xhci` crate under Apache-2.0. That is supply chain by another route, and pretending otherwise
> because it does not appear in `Cargo.lock` would be exactly the under-claiming this paragraph was
> written to correct, inverted.
>
> The two fail differently, which is why the choice was made this way. A dependency is **live** —
> it updates, its own dependencies update, and the reviewable unit is a version requirement rather
> than a body of code. Vendored source is **frozen**: reviewed once, in full, at a known version,
> changing only when somebody changes it here. Worse for maintenance, better for a kernel.
>
> What does not change is responsibility. A license grant covers the right to use code; it does not
> make it correct and it does not transfer the consequences. Vendored code is budgeted, gated,
> tested and reviewed as this project's own — `third_party/README.md` says so, `NOTICE` lists every
> component, and each carries a `PROVENANCE.md`. **The number to watch is no longer "zero
> dependencies" but "what is in `third_party/`, and has anyone read it".**

**And the strongest fact in this document, which it had been under-claiming**: twenty packages in
`Cargo.lock`, all of them `bhaskix-*`. **The shipped workspace has zero external dependencies**, and
`tools/check-deps.py` fails the build if one appears — a **manifest**-level check, not a lockfile one, which is equivalent here only because there is no external *direct* dependency for a transitive to arrive under. The out-of-scope table above is corrected
accordingly.

> **A correction inside the correction, made the same day, because it is exactly the mistake this
> document exists to catch.** The first version of the row above said the keeping-check *did not
> exist* — "the build should fail on a non-`bhaskix` package entering the lockfile, and does not
> yet". **That was wrong.** `tools/check-deps.py` has been enforcing it, in `make gates`, in CI, for
> longer than this reassessment took: it rejects any external crate not explicitly allowed and
> prints the allowed set. It was asserted absent without being looked for, which is the same failure
> as asserting a mitigation present without checking — the direction differs and the discipline does
> not. What is true: the gate exists, its allow-list holds one name, and that name is reachable only
> from `fuzz/`, a separate workspace that never ships.

**If you find that a mitigation listed as "in scope" does not actually work, that is a security bug
and we want the report.** See §9.

---

## 2. Capabilities: the foundation

Restated from [architecture.md](architecture.md) §3 because it is the load-bearing security
mechanism.

There is no `root`. There is no user ID in the nucleus. There is no ambient authority — a domain
cannot name a resource it was not given.

```
Capability { object: ObjectRef, rights: Rights, badge: u64 }
```

### Why this eliminates whole bug classes

Most privilege-escalation bugs in conventional kernels have the same shape: code holds *latent*
authority (it runs as root, or in kernel mode with access to everything) and a logic bug lets an
attacker direct that authority at the wrong object. Confused-deputy attacks, TOCTOU on path
resolution, and `setuid` exploitation are all instances.

If authority must be presented rather than possessed, the deputy has nothing to be confused about.
There is no path-name-to-authority lookup to race against: you hold a capability to the object or
you do not.

> **Demonstrated end to end as of M5-05b.** A program in ring 3 invokes a service through a
> capability it holds at index 0 of its own CSpace, and the service identifies it by a badge the
> program cannot read or set. Removing the capability, or the domain, leaves the program making the
> same system calls and reaching nothing — which is the claim above stated as a test rather than as
> a design intention.
>
> **Delegation demonstrated from user mode as of M5-07.** The same program derives a second,
> differently badged capability to the endpoint, calls through it, revokes the parent, and finds the
> derived copy dead — all by `Invoke` methods on capabilities it holds, with no new system call. A
> domain can therefore only ever delegate what it was itself given.
>
> Still missing: `GRANT` *between* domains is implemented and has no test, so the cross-domain half
> of delegation is written rather than shown.

### Rules the implementation must uphold

1. **Unforgeable.** A capability is an index into a kernel-owned CSpace. Userspace holds an integer
   that means nothing outside its own CSpace. Guessing gains nothing.
2. **Monotone derivation.** `derive(cap, rights)` requires `rights ⊆ cap.rights`. Enforced in one
   function, tested exhaustively.
3. **Immediate transitive revocation.** `revoke(cap)` invalidates every capability derived from it,
   transitively, *before returning*. Deferred revocation is a vulnerability with a delay fuse.
4. **Granter-set badges.** The holder cannot read or alter its badge. This is what lets a userspace
   service authenticate its callers without trusting them — and therefore what lets RBAC live in
   userspace.

Since [RFC 0008](rfc/0008-syscall-and-ipc-shape.md) was accepted and M5 implemented it, these are
statements about named functions with named tests rather than aspirations:

| Rule | Enforced by | Checked by |
|---|---|---|
| 1 — unforgeable | `cap::CSpace`; a domain holds a slot index, never a pointer | A ring 3 program is refused a slot it was not given, before any service is reached (M6-05) |
| 2 — monotone derivation | `cap::Arena::derive`, one function | Exhaustive over all 64×64 rights pairs, on the host |
| 3 — immediate transitive revocation | `cap::Arena::destroy_subtree`, a fixed-point sweep | A derivation tree is revoked at an interior node and every descendant is dead *before the call returns* — and ring 3 revokes its own derived capability and finds the next call refused (M5-07). **And for the memory they name, since 2026-08-23** — revoking a lending takes the page out of the borrower's address space and gives the address back, while leaving the lender's own mapping and the object alive ([RFC 0044](rfc/0044-revocation-that-reaches-the-mapping.md)) |
| 4 — granter-set badges | The badge is copied from the capability by the kernel and is never read from the caller's frame | Taking the badge from the frame instead makes a service unable to tell its callers apart, which fails the gate (M5-05) |

**Each of those checks has been shown to fail** when the rule it guards is deliberately broken. A
gate that has never failed is a gate nobody has tested.

> **Rule 3 had a hole, found and closed 2026-08-23.** It held for
> *capabilities* and not for the **memory mappings** a revoked capability
> named: `method::REVOKE` destroyed arena nodes and never unmapped, so a
> domain that borrowed a page kept reading the frame after the lender had
> revoked the loan, unpinned it and refilled it. The kernel's own words for
> why that is wrong were already in the tree, on `shared::revoke`: *"a revoked
> capability whose pages are still mapped is not revoked, it is renamed."*
>
> Closed by [RFC 0044](rfc/0044-revocation-that-reaches-the-mapping.md), and
> the shape of the fix is worth keeping because the obvious one was worse than
> the bug. Revocation now takes the mapping out of the address spaces of the
> holders that lost their **last** capability naming the object — not every
> holder in the revocation tally, because `bin/fsd` derives what it lends from
> the capability naming its own cache frame and is in that tally on every file
> read; and not by way of `shared::revoke_capability`, which destroys the
> object and would have handed that cache frame back to the allocator
> mid-read. The address is given back too, region record and page-table
> entries both: clearing only the entries left the borrower unable to map
> there again, which is how the hole was found — a hosted program could read
> one file per machine and not two.
>
> Gated two ways, each watched red. A kernel self-test asserts all four halves
> at once — the borrower's page gone, the lender's kept, the object alive, the
> address free — and no plausible wrong fix passes all four. And end to end,
> **two hosted programs read a file on the same boot**, which is a count
> rather than a match: one is the old behaviour.

### RBAC is policy, built on this mechanism

Phase 3's role-based security is a userspace service (`bhaskixd-authz`) that holds capabilities and
hands out derived, badged, rights-reduced capabilities according to a role policy. The nucleus knows
nothing about roles, users, or organisations. This means:

- The RBAC service can be replaced without touching the kernel.
- A bug in RBAC cannot grant authority the service did not itself hold.
- Different editions (desktop, server, hypervisor) can ship different policy services against the
  same kernel.

---

## 3. Boot integrity

> **None of this is built.** There is no TPM code, no PCR extension, no attestation and no
> signature verification anywhere in the tree — `grep -riE '\bpcr\b|attest|secure ?boot'` over
> `*.rs` returns nothing on this subject. What follows is the intended chain, and it is written in
> the present tense throughout, which is how one of its bullets came to describe a handoff field
> that has never existed. Read it as a design.

```
UEFI firmware (Secure Boot)
   │  verifies signature  ─────────────────────────► PCR 0-7  (firmware, config)
   ▼
Limine (signed, shim-loaded)
   │  measures kernel + initrd before jumping ─────► PCR 8-9
   ▼
Bhaskix kernel (signed)
   │  measures the service set and boot policy ────► PCR 10-11
   ▼
Domain 0 / init (measured)
```

- **Secure Boot** gives us a verified chain: nothing unsigned executes.
- **Measured boot** gives us an *attestable* chain: the TPM PCRs record what actually ran, and a
  remote verifier can check it. Verification prevents; measurement detects. We do both, because
  Secure Boot alone cannot tell you *which* signed thing ran.
- The TPM event log has **no path into the kernel**. This document said until 2026-08-12 that it
  "is passed through `Handoff.tpm_event_log`"; no such field has ever existed, and carrying one
  will mean a new handoff field and a `HANDOFF_VERSION` bump.
- **Sealing:** disk encryption keys are sealed to a PCR policy. A tampered boot chain cannot unseal
  them. The failure mode is "the disk does not decrypt", not "the disk decrypts for an attacker".

Our own signing keys, key rotation policy, and how community builds are signed differently from
release builds are governance questions — see [../GOVERNANCE.md](../GOVERNANCE.md). **Nobody ships a
release-signing key in a git repository.**

---

## 4. Hardware-assisted protections

Enabled at boot, verified present, and **refused-to-boot-without** where the guarantee is
load-bearing:

| Feature | Purpose | If absent |
|---|---|---|
| NX / `EFER.NXE` | Non-executable data pages | **Refuse to boot** — W^X is unenforceable without it |
| SMEP | Kernel cannot execute user pages | **Refuse to boot** on CPUs that have it disabled by firmware; warn on CPUs predating it |
| SMAP | Kernel cannot read/write user pages except via `copy_*_user` (which brackets with `STAC`/`CLAC`) | Warn loudly; degraded mode noted in attestation |
| UMIP | User mode cannot read descriptor-table registers | Warn |
| CET (shadow stack, IBT) | Control-flow integrity | Enable when present; not required |
| IOMMU (VT-d / AMD-Vi) | DMA containment | **Boot in degraded mode, printed at boot and recorded in attestation.** T3 and T4 are not mitigated without it. **Enabled on real hardware for the first time 2026-08-24** — an SR550 with 48-bit tables built from `SAGAW`, the AHCI and xHCI controllers each behind their own page table and domain, 105 undrivable endpoints passed through by name, and interrupt remapping on. What follows was true until that boot and is kept because it is how long it took: ~~**And on real hardware it has never been enabled**~~ — found 2026-08-23 on the first machine whose boot report anybody could read: four units discovered and none programmed, because `iommu_bringup` sequences itself after `virtio::probe()` and no real server has a virtio block device. So T3 and T4 are mitigated **for the devices this kernel drives, and on the emulator only** until that is fixed. The second half of that was found on 2026-08-23 too, by surveying the bus: even the `iommu` lane has **three endpoints with no window** — a display adapter, a SATA controller and an SMBus — while translation is enabled. They fault nothing because nothing drives them, and the guarantee has never covered them. This row says so rather than letting the table imply otherwise. **Two, as of 2026-08-24**: RFC 0046 step 2 gave the SATA controller a driver, a window and a domain of its own, so the one real bus master of the three is now contained on the lane that exercises the unit. **And since [RFC 0043](rfc/0043-an-iommu-on-a-machine-with-no-virtio.md) step 4, later the same day, the remaining two are *passed through* rather than absent** — the display adapter and the SMBus now hold context entries with `TT` = `10b`, so they reach all of memory instead of having their DMA refused. **That is a deliberate loosening on the emulator and the price of enabling translation on real hardware at all**, where those endpoints reached everything already because no unit could be turned on. The boot names each one and says it is *not contained*; a reader who sees "iommu enabled" is told, per device, which devices that covers. **A correction owed on 2026-08-25, and larger than the ones above it:** every claim in this row up to here was made while this kernel programmed **one** remapping unit — `dmar.units().next()`, the first structure in the firmware's table — and treated it as the IOMMU. The SR550 describes **four**, and the one carrying `INCLUDE_PCI_ALL`, which governs the PCH and therefore the xHCI, was the fourth. So on 2026-08-24, the boot this row calls "enabled on real hardware for the first time", **most of that machine's devices were governed by units that were never turned on** — untranslated, reaching all of physical memory, while the report said they were contained. The sentence "the AHCI and xHCI controllers each behind their own page table and domain" was true of the tables and false of the hardware. [RFC 0049](rfc/0049-every-unit-the-firmware-named.md) programs every unit the firmware names, with a shared root table, and was measured on that machine the following day: `all 4 units programmed`, and the first genuine DMA refusal this project has ever recorded from real hardware — `unit 3: 00:14.0 was refused a read of 0xaa95f000`. Containment on a multi-unit machine dates from RFC 0049 and **not** from the boot the previous sentence celebrates. |
| KASLR | Randomise the kernel image | Always on; `nokaslr` is a debug-build-only option. **The slide is not printed in the boot report** since 2026-08-23 — see the note below |
| `RDRAND` | The machine's only source of unpredictability ([RFC 0021](rfc/0021-unpredictability.md)) | **Boot, warn loudly, and let the caller refuse.** A machine with no `RDRAND` still has a filesystem, a shell and a supervisor, none of which need to be unpredictable — but `bin/tcpd` does not start, because a guessable TCP sequence number is an off-path injection nobody can see. Reported in the `features` line every boot. |

The "refuse to boot" entries are deliberate. Booting with a silently broken guarantee is worse than
not booting, because the operator believes they have protection they do not have.

> **What the boot report may say about the kernel's own address space, decided 2026-08-23**
> ([RFC 0042](rfc/0042-reading-the-boot-report-back.md)).
>
> The boot report became **readable from ring 3** — a program holding a console capability with
> `READ` can ask for what the kernel printed, which is what makes a machine whose report scrolls off
> a framebuffer diagnosable at all. That turns every address in the report into something a program
> can be told.
>
> The report was audited for what is actually secret, rather than assumed:
>
> | Printed | Secret? |
> |---|---|
> | The KASLR slide | **Yes.** `LINK_BASE + slide` is where the kernel is, which is the whole of what KASLR hides |
> | `hhdm base` | No — a **compile-time constant**, `0xffff800000000000`, stated in `architecture.md` and unchanged since |
> | ACPI `RSDP`, SMBIOS | No — firmware **physical** addresses, findable by anything that can read ACPI |
> | Fixed-table sizes, device windows, source locations | No — sizes and offsets, not the base they are relative to |
>
> So exactly one line changed. The report says `kaslr applied and confirmed`, and the number is
> behind **`kaslr=show`** on the command line — an escape hatch in the same shape as `iommu=off`,
> available only to somebody who already controls the machine enough to hand it a command line.
>
> **What this does not claim.** The report is not *sanitised*, and no filter runs over it: the
> argument is that there was one secret and it was removed at the source. A future line that prints
> a slid address would put it back, and nothing mechanical would notice — which is a real gap, and
> it is stated here rather than closed, because a filter that must recognise every address format is
> a parser with a security obligation and it would be wrong the first time somebody printed an
> address in a new shape.

> **Correction, 2026-08-14.** The KASLR row read *"Randomise kernel image and heap base"* until
> [RFC 0021](rfc/0021-unpredictability.md) went looking for the randomness that would do it. **The
> heap base is not randomised at all**: the heap lives in the direct map, and this machine reports
> `hhdm base 0xffff800000000000` on every boot. The kernel image *is* slid — by **Limine**, not by
> us; `kernel/src/lib.rs` computes the slide it was handed rather than choosing one. Half that row
> was a claim about work nothing performed, and it was unperformable, because until RFC 0021 this
> system had no source of unpredictability to perform it with. Randomising the heap base is a
> separate change with its own risk to the direct map, and it is RFC 0021's open question 2.

---

## 5. Memory safety and the `unsafe` budget

Rust removes memory-safety bugs from safe code. It does not remove them from `unsafe` code, and a
kernel needs `unsafe`. So we manage it as a measured quantity:

- Every crate declares `#![forbid(unsafe_op_in_unsafe_fn)]`. An `unsafe fn` body is not
  automatically an `unsafe` block.
- **Every `unsafe` block carries a `// SAFETY:` comment** stating the invariants that make it sound
  and why they hold here. CI rejects an `unsafe` block without one. A comment that says "this is
  fine" is a review rejection.
- **Per-crate `unsafe` budgets**, declared in `Cargo.toml` metadata and checked in CI. Raising a
  budget requires the PR description to say why. The number is reported on every PR so growth is
  visible rather than gradual.
- **Whole crates refuse `unsafe` outright**, and that is the strongest form of confinement here
  because the compiler enforces it rather than a reviewer: `bhaskix-boot`, `bhaskix-elf`,
  `bhaskix-net` (twice — the crate root and `siphash`), `bhaskix-personality`, `bhaskix-pkg`,
  `bhaskix-telemetry`, `bhaskix-ustar` and — since 2026-08-21 — **`bhaskix-fs`** carry
  `#![forbid(unsafe_code)]`; `bhaskix-mm` denies at its root and forbids in `bump`.
- **`forbid`, not `deny`, wherever the choice is free.** `deny` can be switched off by an `allow`
  anywhere inside the crate, which makes it a default; `forbid` makes the `allow` itself a compile
  error — *"allow(unsafe_code) incompatible with previous forbid"*. For a parser whose entire input
  is bytes somebody else wrote, the guarantee worth having is the one a future edit cannot quietly
  opt out of. `bhaskix-mm` is the deliberate exception: it needs `unsafe` in named places, so it
  denies at the root and forbids in the module that must stay clean.
- Everywhere else, **the budget is the confinement**. There is no module allow-list, and a number
  in a manifest is what a reviewer can actually check.
- `unwrap()`, `expect()`, and panicking indexing are denied outside tests and one-time init paths.
  A panic in the nucleus is a denial of service.

Additionally: `miri` on host-testable crates, `cargo-fuzz` targets on every parser (ELF, filesystem
metadata, network packets, IPC messages), and UBSan/ASan-equivalent debug features in the allocator.

> **Correction, 2026-08-20. The two bullets above replace one that was wrong in three ways**, and it
> had been wrong for long enough that it was quoted rather than checked. It read: *"`unsafe` is
> confined to designated modules: `arch::*`, each driver's `hal` submodule, and the allocator
> internals. Business logic in `fs`, `net`, `sched`, and service code contains none, and CI enforces
> that with a `#![forbid(unsafe_code)]` at those crate roots."*
>
> 1. **There is no module allow-list, and there never was one to enforce.** `unsafe` lives in 25
>    files in `kernel/` and 21 in `arch/`, plus 24 other crates. The kernel's own manifest carried
>    the same sentence — *confined to `sync`, `framebuffer`, `trap` and `faultinject`; no other
>    module may contain `unsafe`* — directly above a dated growth log that records it spreading into
>    `memory`, `vm`, `stack` and per-CPU bring-up. **The header was refuted by the history printed
>    underneath it**, and both are in one file that reviewers read.
> 2. **There is no `hal` submodule anywhere in the tree.** [RFC 0014](rfc/0014-driver-framework.md)
>    chose `register_block!` and `Mmio<T>` instead, which is a better answer — the sentence just
>    outlived the design it described.
> 3. **`sched` — named in that sentence as containing none — has 36 lines.** And this is the part
>    worth keeping: **almost all of them are calls into `arch`**, not dangerous work.
>    `cpu::disable_interrupts()`, `fx_save`/`fx_restore`, `bhaskix_context_switch` — `arch` exposes
>    them as `unsafe fn`, so calling one needs a block, and the metric counts that block's line the
>    same as it counts a raw pointer dereference. **A module's number does not distinguish doing
>    something dangerous from asking `arch` to**, and a reader who does not know that will read
>    every number on the table as worse than it is.
>
> What is true is what the bullets now say, and it is not a weaker claim: **eight crates forbid
> `unsafe` at their root** — `boot`, `elf`, `net`, `personality`, `pkg`, `telemetry`, `ustar` and,
> since 2026-08-21, `fs` — and `mm` denies at its root while forbidding in `bump`, so nine refuse it
> at compile time in whole or in part; every other crate declares a budget the build enforces, and every block
> carries a `// SAFETY:` comment CI requires. **The confinement was real. The description of it was
> written once, at M1, and never checked again** — which is the same failure this document found in
> `architecture.md` §7 the same day, and the reason both now name what enforces them.

**Parsers are where kernels get exploited.** Every parser that touches untrusted input gets a fuzz
target before it gets merged, not after.

> **And a target is not the same as coverage, which was measured on 2026-08-21 rather than assumed.**
> Every one of the fourteen targets was instrumented with probe points and run from an **empty**
> corpus — what a fresh clone has, since `fuzz/corpus/` is gitignored. Most were healthy. Three were
> not: `pkg_manifest` reached **none** of its five points in 1,523,042 executions, `pkg_package`
> none of five in 5,384,466, and `ustar_parse` one of five in four million — though five of five
> with its corpus, which meant its assurance lived in an untracked directory rather than in the
> repository.
>
> **All three were seeded on 2026-08-21** and re-measured from empty corpora: each now reaches what
> it never reached, in tens of thousands of executions rather than millions of futile ones. The
> technique is `fs_image.rs`'s — build the valid structure inside the target and let the fuzzer
> mutate within it, re-deriving whatever integrity value the structure requires. **Recomputing a
> checksum is the threat model, not a cheat**: it defends against corruption, not against somebody
> who can write the file.
>
> Two further findings, both worse than a coverage hole. `arp_parse` and `tcp_parse` **had not
> compiled since 2026-08-18**, when RFC 0029's renames landed: they ran zero executions for three
> days while this section went on claiming a target on every parser. `tools/check-fuzz-targets.sh`
> now runs in `make gates` so that cannot recur. And the analyses that predicted which walls would
> hold were **wrong in the reassuring direction**: a 16-bit checksum is not a wall to a
> coverage-guided fuzzer; a 32-bit one and a 48-bit address are.

---

## 6. Isolation between domains

| Boundary | Mechanism |
|---|---|
| Memory | Separate page tables; no shared mappings without an explicit shared-memory capability |
| CPU | `ResourceEnvelope` enforced by the scheduler ([scheduler.md](scheduler.md) §3) |
| Physical memory | **Weaker than this row claimed.** The per-frame `owner: DomainId` exists and is never written; the envelope (`domain::charge_frames`) bounds **shared objects only**, not a domain's own address space — [memory.md](memory.md) §2 |
| Devices | Per-device IOMMU domain; a device is reachable only via capability |
| A domain that holds another | A supervisor reaches into a domain **only** through a `Domain` capability carrying `WRITE`, and only into domains it was given one for — [RFC 0032](rfc/0032-a-supervisor-interface.md). Revoking that capability ends the reach before the call returns. The reach is one-directional: the held domain gains nothing, and its CSpace stays empty |
| IPC | Endpoints are capabilities; there is no global name service to enumerate |
| Time | **Not a boundary today.** Coarse *and* fine-grained time are both free to every domain: `rdtsc` is unprivileged and `CR4.TSD` is never set. See the correction below |

**Frames are zeroed on allocation, not on free.** Zero-on-free is a common choice and it is the
wrong one: it puts the cost on the freeing path (often latency-sensitive teardown) and it can be
skipped by a crash. Zero-on-allocation cannot be skipped, because the receiving domain's correctness
depends on it. A frame never reaches a domain carrying another domain's data.

> **This paragraph was not true of shared memory objects until 2026-08-26, and the correction stands
> here rather than only in the changelog.** The last sentence was written as a property of the system
> and was a property of one path: `AddressSpace::map_anonymous` zeroed, and `shared::create` did not.
> Objects created by the nucleus and handed to ring 3 services — the Linux adapter's report page, the
> telemetry rings, the network rings, a lent page — arrived carrying whatever the previous tenant of
> those frames had left. Measured on one boot before the fix: **40 of the frames behind 12 objects
> were non-zero, and the worst page carried 3,546 non-zero bytes.** With the fix reverted on purpose
> the staging gate reports the full 4,096.
>
> **What it was and what it was not.** It is an information disclosure across the domain boundary
> this table exists to describe, and it reached real ring 3 services on every boot. It is **not**
> remotely triggerable and never was: no system call creates a shared object, so an attacker could
> not ask for frames and read them — every caller of `shared::create` is in the nucleus, and what a
> service received was whatever the allocator happened to hand back. That bounds it; it does not
> excuse it, because the boundary is the claim this document makes.
>
> It was found by a reader that assumed the paragraph above was true: the kernel began printing the
> Linux adapter's fault log, whose unwritten entries should read zero, and two of them held a
> canonical kernel-half address and a plausible user address. The policy itself is now written down
> in [memory.md](memory.md) §2, which is where the code had been citing a section that did not
> contain it.

**Filesystem data blocks follow the same rule, and for once the code was ahead of the document.**
The paragraph above is about memory frames; disk blocks are a separate allocator with the same
exposure, and nothing here said which way they went. They go the same way: `Volume`'s write path
zeroes a block on the `fresh` arm — the one taken when a block has just been claimed from the
bitmap — before any of the writer's own bytes land in it. `remove` does not clear the blocks it
frees, only their bits in the bitmap, so the bytes of a deleted file stay on the device until
something else is given that block. That is zero-on-allocation, arrived at for the same reason:
the receiving file's correctness depends on it, so it cannot be skipped.

This matters here because `bin/linuxd` holds one directory capability on behalf of *every* hosted
process, so two hosted processes are separated by the filesystem's guarantees and not by a
capability boundary. Both halves are now asserted by
`a_data_block_is_zeroed_when_it_is_allocated_not_when_it_is_freed` (`fs/src/volume.rs`) — the bytes
survive the free, and are gone by the time another file can address them — and the test was armed
by deleting the zeroing and watching it go red on the second half. A second, independent guard sits
above it: `Filesystem::read` refuses to read past the size an inode declares, whatever its block
pointers say.

> **RFC 0069 asserted the opposite and was wrong.** Its confidentiality paragraph reads *"a block
> freed by `remove` and reallocated is already handed out without zeroing"*, and concluded from
> that premise that the RFC introduced no new exposure while making the first allocation after a
> format share the same weakness. The premise was never checked against the write path. The
> conclusion — no new exposure — happens to hold, and holds more strongly than the RFC claimed, but
> it was reached from a false statement about how the allocator behaves. The RFC's own paragraph is
> corrected in place rather than only here.

**The Time row said "fine-grained timers are rate-limited per domain (side-channel hygiene)" until
2026-08-26, and no such limit has ever existed.** There is no rate limiter anywhere in this kernel,
per domain or otherwise. The finest-grained clock on the machine is `rdtsc`, and `arch/x86_64`'s own
comment states the position: *"`rdtsc` is readable at every privilege level unless `CR4.TSD` is set,
which this kernel never sets."* `syscall.rs` says the same from the other side, explaining why
arming a deadline is a service worth having — a program *"can already read the clock, since `rdtsc`
is unprivileged here."* So every domain has cycle-resolution timing, unrestricted, and the row
described a mitigation rather than a mechanism.

**The two halves of this document disagreed with each other.** §1 already lists microarchitectural
side channels as **out of scope**, with mitigation deferred to Phase 3 and marked *"Documented gap
until then"* — which is the honest position and the one the project has taken elsewhere. The
isolation table then claimed, in the present tense, that a timing mitigation was in place. A reader
checking whether this system defends against timing attacks would have found the answer twice and
got two different ones.

**What is true.** Deadlines (RFC 0019) are capabilities like everything else, so a domain can arm
only as many as it holds notification capabilities for, bounded by `max_capabilities` in its
envelope. That is a bound on how many, not on how often, and it is not a side-channel measure — it
is the ordinary capability accounting that applies to every object. Whether to set `CR4.TSD` is a
real decision with real costs (hosted Linux programs read the TSC directly, and so does this
kernel's own measurement code), and it is the project lead's to make rather than something to be
implied by a table.

### A Linux compatibility domain is a domain, and nothing in this table changes for it

Every boundary above applies to a hosted Linux workload unchanged, and it is worth saying why
rather than assuming a reader will infer it. **Linux privilege does not appear in this table**,
because there is nothing for it to appear as: authority here is a capability a domain holds, and
`root` inside a compatibility domain is a number in that domain's own process table. It buys the
files, ports and processes the domain was already granted, and nothing else, because there is no
mechanism by which being UID 0 could add a capability.

```text
Linux UID 0                   ≠  Bhaskix unrestricted authority
Linux application compromise  ≠  Bhaskix system compromise
```

Both lines are properties a test may attempt to violate rather than assurances — see
[RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md) §6, which specifies four of them.
**Two of the four are largely funded by gates that already run** (driver containment and
capability revocation); the Linux-facing two are not written yet, and the row above says so.

---

## 7. Secure update (Phase 3, specified now)

- **Immutable root.** The system image is read-only and integrity-verified at runtime (dm-verity
  equivalent). Configuration and state live in separate, writable, non-executable volumes.
- **A/B slots.** An update writes the inactive slot, verifies its signature and hash, then switches
  the boot pointer atomically. A failed boot rolls back automatically after N attempts.
- **Rollback protection.** A monotonic version counter in TPM NVRAM prevents an attacker from
  installing a genuinely-signed *old* image with a known vulnerability. Signed-but-outdated is a real
  attack and signature checking alone does not stop it.
- **Atomic or nothing.** There is no partially-updated state. This is a correctness property as much
  as a security one — an OS that can be interrupted mid-update during a power failure is not an
  enterprise OS.

---

## 8. Audit and attestation

The audit framework is **not a separate subsystem**. It is a consumer of the typed telemetry plane
described in [ai-native.md](ai-native.md) §2. This is deliberate: one event pipeline, one schema,
one place to get the semantics right.

The plane exists as of [RFC 0026](rfc/0026-telemetry-plane.md) (accepted 2026-08-17), and the
`Audit` class is **reserved and refused** in it: emitting the class is counted and dropped,
because a best-effort audit event is false assurance with a checksum. The backpressure ring, the
hash chain and audit-grade naming are a future RFC on that foundation, and this section is its
requirements list.

Audit-specific requirements on top of the telemetry plane:

- **Tamper-evident.** Records are hash-chained; each entry commits to its predecessor. Removing or
  altering an entry breaks the chain and is detectable.
- **Guaranteed capture for audit-class events.** Telemetry may drop events under pressure (it is
  best-effort by design). Audit-class events may not: they apply backpressure instead. The classes
  are separated so that a flood of debug telemetry cannot evict a security record.
- **Remote attestation.** A verifier can request a TPM-signed quote over the boot PCRs plus the
  audit chain head, and thereby check both what booted and that the log has not been truncated.
- **The audit log records capability grants and revocations**, which is the security-relevant event
  set in a capability system — not `open()` calls on paths.

---

## 9. Reporting a vulnerability

Do not open a public issue for a security bug.

Report privately to the maintainers. Contact details and the current state of the reporting
channel are in [SECURITY.md](../SECURITY.md), which also records what is *not* a vulnerability yet —
this project documents its unfinished work in the open, and a report of a protection that is
tracked as unimplemented costs the reporter time for nothing.

We commit to:

- Acknowledgement within 72 hours.
- A coordinated disclosure window of 90 days by default, negotiable for severe or complex issues.
- Public credit to the reporter unless they prefer otherwise.
- A published post-mortem for every issue rated high or critical, including what in our design or
  process allowed it — because "security by design" means treating a vulnerability as a design
  question, not just a patch.

---

## 10. Open questions

- **KPTI-style page-table isolation:** always on, opt-in, or CPU-dependent? Cost is real; so is
  Meltdown-class exposure on older CPUs.
- **Core scheduling** (never co-schedule threads from different domains on SMT siblings): correct
  mitigation for cross-domain SMT side channels, meaningful throughput cost. Default on or off?
- **Attestation format:** align with an existing standard (TCG DICE, IETF RATS/EAT) or define our
  own? Strong lean toward an existing standard — see the open-standards principle.
- **Signing and key custody** for release builds. A governance decision with technical consequences.
- Do we allow unsigned kernels in developer mode, and how is that state made unmistakable to the
  user and to a remote verifier?
