# RFC 0094: A program's vector registers are its own

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-30 — ~~nothing built~~ steps 0-3 built and gated the same day; AVX itself (step 4) and steps 5-8 open. Both questions decided by the lead the same day, each as recommended**: AVX only, AVX-512 waiting on its trigger; the signal half in this RFC, and first (§*Unresolved questions*). Drafted at the lead's request, **ahead of its recorded trigger**: TRACKER's row asks for this RFC when an L1 program needs AVX or a distribution's packages assume x86-64-v3, and neither has happened — Ubuntu 26.04 still ships plain amd64 builds, and the pinned corpus uses one. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | arch / sched / userspace (`bin/linuxd`, `personality`) |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — an unmodified x86-64-v3 Linux program runs |
| **Depends on** | [RFC 0005](0005-linux-abi-compatibility.md) (the row this comes from, carried out at its amendment), [RFC 0083](0083-a-signal-a-process-can-catch.md) (the frame a handler reads), [scheduler.md](../scheduler.md) §6 (the switch path) |

---

## Summary

The kernel enables `XSAVE` and the AVX state component on every CPU that offers them. It saves
and restores each thread's vector registers on every switch with `XSAVEOPT` and `XRSTOR`, where
it now uses `FXSAVE` and `FXRSTOR`. And a caught signal's frame carries the interrupted code's
floating-point state, as Linux's does, so that `rt_sigreturn` puts it back. A program built for
x86-64-v3 then runs, and no thread can see or disturb another's registers. A CPU without `XSAVE`
keeps today's path exactly.

## Motivation

**A program built for x86-64-v3 cannot run here.** The kernel never sets `CR4.OSXSAVE` and never
executes `XSETBV`, so every VEX-encoded instruction raises `#UD`. CI run 874 found this when the
runner's `/bin/busybox` became Ubuntu's `amd64v3` build. It stopped at `vmovdqa` (rip `0x56df50`)
on every boot lane, and the corpus was pinned to the plain amd64 build the same day. Nothing more
was done: the gap went into TRACKER under *Carried out of RFC 0005*, "for an RFC when an L1
program needs it".

A program that asks before it uses AVX runs today, more slowly. Go 1.25.0's
`internal/cpu/cpu_x86.go:121-133` (read 2026-10-30 from the toolchain on the build host) checks
`OSXSAVE`, then `XGETBV` bits 1 and 2, and falls back when either is clear. glibc's dispatch does
the same. A program *compiled* for x86-64-v3 has nothing to fall back to.

**Turning AVX on is not a bit; it is a promise.** `CR4.OSXSAVE` and `XCR0` tell every program
that the system saves the registers they name. This kernel saves 512 bytes per thread, the
`FXSAVE` image (`kernel/src/sched.rs:3453` and `:4744`). That image holds the x87 and `xmm`
registers and **not the upper halves of the `ymm` registers**. Enabling AVX with today's switch
path would let two threads on one CPU read and overwrite each other's upper halves. That is
silent, happens only sometimes, and crosses domains. `enable_sse` says it plainly
(`arch/x86_64/src/cpu.rs:298`): enabling the bits without keeping the promise is "the worst kind
of bug this project can ship".

**And a caught signal does not keep the promise even for SSE.** Read from the code on
2026-10-30, not seen happen:
- `bin/linuxd` builds a handler's frame from the general-purpose registers only. The frame's
  `fpstate` word, at offset 184 of `sigcontext_64` (compiled against this host's
  `<asm/sigcontext.h>`), is left zero.
- `rt_sigreturn` restores general-purpose registers only.
- So whatever the handler leaves in the vector registers is what the interrupted code resumes
  with.

It rarely bites today. RFC 0083 delivers only on the way out of a call or at a fault, and at a
call neither C nor Go keeps a live value in a vector register. The one exception is Go's `X15`,
which Go's signal entry zeroes (`runtime/sys_linux_amd64.s:342`) to the zero Go code expects
anyway. It bites at a fault a handler resumes from, after a raw `syscall` made with live vector
values, and **the day delivery becomes asynchronous** (TRACKER's open `SIGURG` row). Go's
`memmove` holds 16 bytes of the copy in `X15` between `memmove_amd64.s:248` and the store that
follows. A signal arriving in that window would zero those 16 bytes of the copy. With AVX
enabled, the same Go code takes AVX2 paths in `memmove` and `internal/bytealg`, so the frame
must carry the `ymm` state as well.

## What was measured before writing this

All on 2026-10-30.

**What each lane's CPU offers.** Asked of QEMU itself with `query-cpu-model-expansion`, booting
nothing:

| Lane | `XSAVE` | `XSAVEOPT` | `XSAVEC` | AVX, AVX2 | AVX-512F |
|---|---|---|---|---|---|
| QEMU 4.2.1 (this host), TCG `max` | yes | yes | no | **no** | no |
| QEMU 4.2.1, TCG `qemu64` | **no** | no | no | no | no |
| QEMU 10.2.1 (CI's runner, through `tools/boot-on-ci-emulator.sh`'s image), TCG `max` | yes | yes | no | **yes** | **no** |
| QEMU 10.2.1, TCG `qemu64` | no | no | no | no | no |
| KVM on this host (`host` and `max`) | yes | yes | yes | yes | yes |

So the lanes divide three ways, and each way is a path that must stay gated:
- `qemu64` has no `XSAVE` at all;
- local `max` has `XSAVE` without AVX;
- CI `max` and KVM have AVX.

**No CI lane can exercise AVX-512.** Only KVM on this host and the SR550 can.

**What the machine leaves in `CR4`.** QEMU's monitor showed every CPU's `CR4` after boot, on four
paths: Limine under BIOS and under UEFI, each under TCG `max` and under KVM `host`. All four CPUs
read `0x300620` on every path: `OSFXSR`, `OSXMMEXCPT`, SMEP and SMAP set, **`OSXSAVE` clear**.
The native loader and the SR550's firmware have not been read. That matters, because
`enable_cpu_protections` ORs bits into `CR4` and keeps whatever it found. A firmware that left
`OSXSAVE` and `XCR0` set would give its CPU working AVX today, on a switch path that drops the
upper halves.

**What the state costs.** These timings come from a ring-3 program on this host's Xeon Silver
4314 (Ice Lake-SP). `XSAVE`, `XSAVEOPT`, `XSAVEC` and `XRSTOR` behave the same at CPL 3; `XSAVES`
does not run there.
- Each switch is one save into the leaving thread's area and one restore from the arriving
  thread's.
- Two areas are alternated, so `XSAVEOPT`'s "modified" optimisation cannot apply, as on a real
  switch.
- Figures are medians of 400 batches of 2,000 switches, in TSC ticks at the 2.4 GHz base clock.
- The cache is warm, so this is the best case. Three runs agreed to within half a tick.

| State saved | `FXSAVE` | `XSAVE` | `XSAVEOPT` | `XSAVEC` |
|---|---|---|---|---|
| x87 + SSE (today) | **101.8** | 192.3 | | |
| AVX enabled, upper halves unused | | 202.4 | **187.9** | 190.4 |
| AVX in use | | 218.9 | **205.7** | 218.5 |
| AVX-512 enabled, unused | | | 187.9 | 190.4 |
| AVX-512, every component in use | | 265.8 | **230.1** | 266.2 |
| *Hybrid: read `XINUSE`, then `FXSAVE`, when only SSE is live* | 112.2 | | | |

**What those numbers say:**
- Moving from `FXSAVE` to any `XSAVE` form costs about **86 ticks, about 36 ns, per switch**,
  whether or not a thread uses AVX.
- AVX in use adds 18 more ticks.
- AVX-512 enabled and unused adds nothing over AVX: `XSAVEOPT`'s init optimisation skips
  components in their initial state.

**What they do not say:**
- They are not the SR550's CPU.
- They are not the kernel's switch, with its locks and cold areas.
- They are not under TCG, where most lanes run.

Step 6 measures the switch in the kernel itself, on the lanes and on the SR550.

**The layout, from this host's CPU and headers, not from memory:**
- `CPUID.(0Dh,0)` reports `XCR0`-supported components `0x2e7` and 2,696 bytes for all of them in
  the standard format.
- The AVX component sits at offset 576 and is 256 bytes, so an area for x87, SSE and AVX is 832
  bytes.
- The AVX-512 components are 5 (64 bytes at 1088), 6 (512 at 1152) and 7 (1024 at 1664). PKRU is
  9 (8 at 2688).
- The component numbers match `enum xfeature` in this host's Linux 5.15 headers
  (`asm/fpu/types.h`).
- Signal-frame constants are taken from this host's `<asm/sigcontext.h>`, compiled:
  - in `sigcontext_64`, `oldmask` is at 168, `cr2` at 176 and `fpstate` at 184;
  - `_fpstate_64` is 512 bytes, with `sw_reserved` at 464;
  - `_xstate` is 832 bytes;
  - `FP_XSTATE_MAGIC1` is `0x46505853` and `FP_XSTATE_MAGIC2` is `0x46505845`.
- `AT_MINSIGSTKSZ` is 51, from glibc's `bits/auxv.h` here.

**And the nucleus touches no vector register.** The release kernel built for the 2026-10-30 suite
was disassembled: 229,913 lines, **zero** instructions naming an `xmm`, `ymm` or `zmm` register,
and exactly two `fxsave` and two `fxrstor`, the two switch sites. Its target enables only `x87`
and `fxsr` (`rustc --print cfg --target x86_64-unknown-none`). A user thread's vector state
therefore stays in the registers untouched while the kernel runs, until a switch saves it. That
is the property the whole design rests on. Step 0 makes it a gate.

## Design

### What is enabled

The boot CPU reads `CPUID` and chooses `XCR0`:

| The CPU offers | `XCR0` | Switch instruction |
|---|---|---|
| no `XSAVE` | none: `CR4.OSXSAVE` **cleared** | `FXSAVE` / `FXRSTOR`, as today |
| `XSAVE`, no AVX | `0x3`: x87, SSE | `XSAVEOPT` (or `XSAVE`) / `XRSTOR` |
| `XSAVE` and AVX | `0x7`: x87, SSE, AVX | `XSAVEOPT` (or `XSAVE`) / `XRSTOR` |

**Not enabled:**
- MPX (components 3 and 4), withdrawn by its maker;
- AVX-512 (5–7): question 1;
- PKRU (9): protection keys are not used here and `CR4.PKE` stays clear;
- AMX (17 and 18): 8 KiB of tile data per thread, and a permission protocol Linux programs must
  ask for;
- any supervisor component: `IA32_XSS` is left alone.

**`XSAVE` whenever it is offered, even without AVX.** On local `max` lanes that costs about 90
ticks a switch and buys nothing those lanes use. But without it the `XSAVE` path would run on no
local lane at all. It would be seen only on CI and the SR550, and *local green is not CI green* is
already a lesson this project has paid for.

**`CR4.OSXSAVE` is set to the choice, not left as found.** When the choice is "none", the bit is
cleared explicitly, so a firmware that set it cannot hand a CPU an AVX the switch does not save.

### On every CPU

`enable_sse`'s successor runs where it does, before anything enters ring 3 on that CPU:
1. It sets `CR4.OSXSAVE` (bit 18) and executes `XSETBV` with the boot CPU's choice.
2. It reads the choice back with `XGETBV`.
3. An application processor whose `CPUID` cannot honour the boot CPU's choice is not brought into
   service. Its line in the report is red: a thread migrated onto it would fault on its own
   state.

### The area

`FxArea` becomes `FpArea`, `#[repr(align(64))]` (`XSAVE` needs 64), with room for 832 bytes. It
stays **inline in `Thread`**, as today. A steal (`try_steal`, `sched.rs:2568`) moves a `Thread`
by value, so it now copies 832 bytes instead of 512. The 512 thread slots (64 CPUs × 8) grow by
160 KiB in all.

The kernel compares `CPUID`'s own offset and size for each component it enables against that
room, rather than trusting 576 and 256. If a component does not fit, it enables less and reports
it in red.

**The initial image is written from constants, as today's is.** The legacy region holds `FCW`
`0x037f` and `MXCSR` `0x1f80`. The 64-byte `XSAVE` header that follows is all zero. An `XRSTOR`
of a zero `XSTATE_BV` puts every enabled component in its initial state. That was observed on
this host while measuring: after one, `XGETBV(1)` read `0x203`, so nothing beyond x87, SSE and
the host's own PKRU was in use. Nothing is copied from the running CPU, for the reason
`FxArea::initial` gives: a copy hands the new thread its predecessor's registers.

### The switch

At both switch sites, `XSAVEOPT` into the leaving thread's area and `XRSTOR` from the arriving
thread's, with the instruction mask set to `XCR0`. `XSAVE` is used where `CPUID.(0Dh,1):EAX[0]`
says `XSAVEOPT` is absent.

**One rule makes `XSAVEOPT` sound here**, ~~recalled from the SDM and to be checked against it in
step 2~~ **checked 2026-10-30 against the instruction reference derived from the SDM**: its
"modified" optimisation may skip saving a component that has not been modified since the last
`XRSTOR`, when that `XRSTOR`'s CPL, VMX mode and area address match this save's (`XRSTOR_INFO`).
In short, it may skip a component the CPU believes unchanged since the last `XRSTOR` from the
same address. So software may write an area only while its
thread is off every CPU, and an `XRSTOR` from that area must come before its next `XSAVEOPT`.
Every path that writes an area (the initial image, and step 3's `rt_sigreturn`) writes it while
the thread is stopped, and the thread can only run again through an `XRSTOR` from that area. So
the rule holds by construction. Step 3's gate exercises it: a handler edits the frame's state and
the edit must stick.

### What a hosted program sees

Nothing is intercepted:
- `CPUID.1:ECX.OSXSAVE` reads 1, because the hardware reflects `CR4`.
- `XGETBV` returns `0x7`.
- Go, glibc and musl then choose their AVX2 paths.

A program that tests `CPUID`'s AVX-512 bit and never asks `XGETBV` faults on the SR550. That
skips the check Intel documents and every runtime named above makes, and it is not designed for.

Native Bhaskix programs are built for `x86_64-unknown-none`, which enables neither SSE nor AVX,
and are unaffected.

### Signal frames carry the state

1. **Delivery.** `bin/linuxd` asks for the stopped thread's area. The image does not fit a fault
   slot: 512 bytes, 168 already used. So two calls on the fault object `linuxd` already holds
   read and write a slot's floating-point image through a page it maps. These calls are made only
   at a delivery and at `rt_sigreturn`, never on an ordinary call, which pays nothing. `linuxd`
   then writes the image into the frame in Linux's layout:
   - **With `XSAVE`:** 64-byte aligned below the `ucontext`, its address in `fpstate` at offset
     184. `sw_reserved` (at 464) carries `FP_XSTATE_MAGIC1`, `extended_size`, `xfeatures` and
     `xstate_size`, and `FP_XSTATE_MAGIC2` follows the image.
   - **Without `XSAVE`:** the 512-byte `FXSAVE` image, with `magic1` zero.

   The handler starts from the initial state. That is Linux's behaviour as recalled; step 3
   checks it against Linux's own `signal.c` before relying on it.
2. **`rt_sigreturn`.** `linuxd` copies the frame's image back through the same call, and **the
   kernel validates it before it is installed**. A bad image found only at the next switch's
   `XRSTOR` would fault in the switch path, so it is refused at the call. `linuxd` is a ring-3
   service, and the image came from a hosted program's stack, so neither is trusted. The
   validator is a pure function in a host-tested crate. It requires:
   - `XSTATE_BV` within `XCR0`;
   - `XCOMP_BV` zero, since this is the standard format;
   - ~~the header's reserved bytes zero~~ **header bytes 8..24 zero** -- `XCOMP_BV` and the word
     after it;
   - `MXCSR`'s reserved bits clear against the CPU's `MXCSR_MASK`.

   These are `XRSTOR`'s `#GP` conditions ~~as recalled from the SDM; step 3 checks each against
   it~~ — **checked 2026-10-30 against the instruction reference, and one was wrong as recalled**:
   the standard form checks header bytes 8..24, not the whole reserved remainder to byte 64.
   Refusing bytes 24..64 too would have refused frames the processor and Linux accept, so the
   check follows the instruction exactly, and its host test asserts byte 40 is not refused.
   `MXCSR` is loaded whenever SSE or AVX is requested, whatever `XSTATE_BV` says, which is why the
   initial image carries `0x1f80`. The default mask for a processor reporting zero (`0xffbf`)
   is still recalled; every processor met reports its own, read at boot.
   A refused image ends the program with `SIGSEGV`, as Linux does with a bad frame (recalled).
3. **`AT_MINSIGSTKSZ` (51)** joins the auxiliary vector, sized for the frame with its image.
   `FRAME_BYTES` grows by the image and its alignment, at most 900 bytes with AVX.

**The `cr2` word is mis-placed, filed separately.** `personality::signal::sigcontext::CR2` is 168,
which is `oldmask`'s offset. Linux's `cr2` is at 176, and its host test asserts the same 168, so
the test cannot see it. The frame code is the same code this step touches. The defect is filed in
TRACKER, not folded in here.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Lazy switching** (`CR0.TS`, save on the first `#NM`) — what `scheduler.md` §6 still says this kernel does | It leaks. **CVE-2018-3665 (LazyFP)**: on affected Intel CPUs, a process can speculatively read another's FPU, SSE and AVX registers while they are still loaded. Intel's guidance is eager restore (Red Hat's advisory, read 2026-10-30). The measured saving is 36 ns a switch, and the cost is a cross-domain leak. The code has been eager since 2026-08-19; the document was never corrected. | Never on an affected CPU. |
| **The hybrid**: read `XINUSE` with `XGETBV(1)`, use `FXSAVE` while only SSE is live | 112 ticks against 188: it saves about 76 per switch for threads that never use AVX. But each area could then be in either of two formats. And a thread restored with `FXRSTOR` after one that used AVX must have the upper halves cleared first, **or it reads the previous thread's**: a leak, made by a shortcut. `XGETBV(1)`'s availability under TCG is not measured. | Step 6 shows switches are where the time goes on a workload that matters, and then with its own leak gate. |
| **`XSAVEC`** (the compacted format) | Neither QEMU offers it (table above), and it was slower than `XSAVEOPT` in every in-use case measured (218.5 against 205.7 with AVX; 266.2 against 230.1 with AVX-512). It would also need the standard format reassembled for every signal frame. | Large components, AMX's in particular, make compaction's memory saving matter. |
| **`XSAVES`** (compacted, supervisor-only) | Linux uses it because it keeps supervisor state; there is none to keep here. It runs only at CPL 0, so it was not measured. | A supervisor component (for example CET's shadow-stack state) is enabled. |
| **`FXSAVE` unless AVX is offered** | Saves about 90 ticks on local `max` lanes, but leaves the `XSAVE` path unexercised on every local lane. | Never on the lanes; perhaps as a build option for a CPU class that matters and has `XSAVE` without AVX. |
| **An area allocated apart from `Thread`** | At 832 bytes, the inline copy on a steal costs less than the allocator and the pointer chase would. | Question 1 is answered "AVX-512 too": 2,752 bytes per slot, 1.1 MiB more in all, and copied on every steal. |
| **Leave AVX off; pin plain-amd64 builds** — today | It works as long as plain builds exist. The BusyBox pin is exactly this. | It is the status quo until the trigger fires, which is why this draft says it was written early. |

## Impact on existing design documents

- **`docs/scheduler.md` §6** says: *"FPU/SSE/AVX state is switched lazily via `CR0.TS` /
  `XSAVE`, not eagerly."* That has been wrong since 2026-08-19, when SSE arrived with an eager
  `FXSAVE`. It is corrected in place now, in this draft's own change, with what the code does and
  why lazy is rejected. On acceptance it states the `XSAVE` design.
- **`docs/security.md` §1**: a line under the isolation threats saying the vector registers are
  saved eagerly and why (CVE-2018-3665), and that step 2's gate proves no thread reads another's.
- **The guides** state the limit today:
  - `linux-programs.md`: "not an x86-64-v3 build";
  - `overview.md`: "static x86-64 binaries without AVX";
  - `faq.md`: "built for AVX-capable CPUs (x86-64-v3) ... do not run yet".

  Each is rewritten when step 5 is green, not before.
- **TRACKER**: the *Carried out of RFC 0005* row points here, and two defects are filed: the
  signal-frame gap and `cr2`.

## Security implications

- **No new authority.** The two calls are made on the fault object `bin/linuxd` already holds,
  for threads it already reads and edits the registers of.
- **The risk this RFC exists to remove is information flow between domains through the vector
  registers.** It comes in three shapes, and each is ruled out by a gate, not an argument:
  - AVX enabled without saving the upper halves (step 2's arm);
  - lazy switching (rejected above);
  - an area restored in the wrong format (no second format exists; the hybrid is rejected).
- **A new parser of untrusted input**: the frame image `rt_sigreturn` hands the kernel. Its
  validator gets a fuzz target (`coding-style.md` §8), and the property is that anything it
  accepts, `XRSTOR` accepts. The step-3 lanes check that property on real instructions, and the
  host fuzzes the structure.
- **A firmware's leftover `CR4.OSXSAVE`** is closed by setting `CR4` to the choice rather than
  OR-ing into it.
- **AVX-512's frequency effects.** On Skylake-SP, the SR550's CPU class, heavy 512-bit work
  lowers the core's clock, and with it the clock of whatever shares that core. This is recalled,
  not measured here. A cost one domain imposes on another is a reason in question 1, not a
  settled fact.

## Performance implications

**Slower:** every switch on a CPU with `XSAVE`, by about 86 ticks (36 ns) on this host's CPU, and
18 more when the thread uses AVX. Signal deliveries, by two calls and up to 900 bytes copied each
way.

**Faster:** an x86-64-v3 program runs at all. A Go program's `memmove` and `bytealg` take their
AVX2 paths, which Go chose for being faster. That gain is not measured here.

**What will be measured** is the kernel's own switch: the `cost` line gains save-and-restore
ticks per switch, on every lane and on the SR550 (step 6).

## Testing plan

**On the host:**
- the `XCR0` choice as a pure function of `CPUID` values, tested with the five lanes' values in
  the table above and the SR550's once read;
- `FpArea::initial`'s bytes;
- the frame's offsets against the values compiled from Linux's headers above;
- the validator, with each refusal armed;
- the validator's fuzz target.

**In QEMU:**
- **A vector probe**, a ring-3 program: two threads on one CPU each fill every register the CPU
  was given with its own pattern, then yield a thousand times and compare. It runs on every lane,
  so each of the three paths is gated where it exists. Where AVX is offered it checks the `ymm`
  upper halves. **Armed**: `XCR0` `0x7` with the `FXSAVE` switch must turn it red.
- **A signal probe**: a handler that writes every vector register and returns. The interrupted
  code then checks its own. It is expected red before step 3, which is how the filed defect is
  proven rather than argued.
- **The v3 BusyBox on CI's `max` lanes**: Ubuntu's `amd64v3` build, pinned by hash beside the
  plain one. `qemu64` cannot run it, and neither can Linux on that CPU.

**Through KVM on this host:** AVX, and AVX-512 if question 1 says so; no CI lane can.

**On the SR550:**
- the `xstate` line;
- its `CR4` as the firmware left it;
- the v3 BusyBox;
- the switch cost.

**A static gate:** the release kernel names no vector register outside the switch's save and
restore. That is true today (zero operands; two `fxsave`, two `fxrstor`). It is checked by
disassembly, so that a nucleus change that starts using SSE cannot silently break the property
the design rests on.

## Unresolved questions

1. **AVX-512: enable it now, or wait?** **Decided 2026-10-30 by the lead: wait, as recommended.** *Recommended: wait*, with a trigger: the first program or
   distribution that assumes x86-64-v4.
   - **For enabling:**
     - the SR550 and this host offer it;
     - unused, it costs nothing per switch (measured);
     - programs that check fall back without it (Go checks `XCR0` bits 5–7, read in its source).
   - **Against:**
     - no CI lane can test it;
     - each area grows from 832 to 2,752 bytes, 1.1 MiB in all, copied on every steal;
     - its frequency effects cross domains (recalled).

   The lead decides.
2. **The signal half: in this RFC, or its own?** **Decided 2026-10-30 by the lead: in this RFC, and first, as recommended.** *Recommended: in this RFC, and first* (step 3,
   before AVX is enabled in step 4).
   - The day `XCR0` offers AVX, Go's runtime starts using `ymm` registers in routines its handlers
     can reach. So a frame that cannot carry them becomes a regression the same day.
   - The gap already exists for SSE, and closing it is a prerequisite of asynchronous delivery
     whatever happens to AVX.

**Left out on purpose:**
- AMX;
- protection keys;
- core dumps and `ptrace` of the vector state;
- **a forked child's floating-point state.** Linux copies the parent's (recalled), and this
  kernel starts every new thread from the initial image. A program that sets a rounding mode and
  then forks sees the difference. Its trigger is the first program found depending on it.

## Implementation plan

0. **Arms first.** The static gate (no vector register in the nucleus), green today. The vector
   probe and the signal probe written, and seen red where they should be: the signal probe today,
   and the vector probe with `XCR0` forced to `0x7` over the `FXSAVE` switch.
   **Done 2026-10-30.** `tools/check-vector-registers.py` in `make gates`: the release kernel
   names no vector, MMX, mask or x87 register outside its save and restore, and the gate's
   self-test refuses seven kinds of violation. The **signal probe was red on the unchanged tree**
   -- `resumed 1, 32 of 32 quadwords wrong (last 0xffffffffffffffff), the handler was handed xmm0
   0x5a5a5a5a00000000` -- the filed defect shown rather than argued. The **vector probe** passed
   under `FXSAVE`; its arm was not the one planned here (`XCR0` `0x7` cannot be seen by a probe
   that uses `xmm` alone, which waits for step 4) but the switch's save skipped at the site
   `yield` takes: `54528 quadword(s) wrong`.
1. **Print what each CPU offers.** An `xstate` line on every boot:
   - the components offered;
   - the size `CPUID` reports;
   - the choice;
   - `CR4.OSXSAVE` as found at entry.

   The choice function is host-tested. This reads the native loader's and the SR550's `CR4`,
   which nothing has yet. **Done 2026-10-30**, six host tests. Read on the lanes: QEMU 4.2.1's
   TCG `max` offers `x87 sse bndregs bndcsr pkru (0x21b)`; KVM on the Xeon Silver 4314 offers
   `0x2e7` (AVX, AVX-512, PKRU, 2,696 bytes); `qemu64` offers no `XSAVE`. `CR4.OSXSAVE` at entry
   0 on all of them, ~~the native loader's lane and the SR550 are still unread~~ the native
   loader's lane included (read once its stack defect, below, was fixed); the SR550 is unread.
   **Step 2 uncovered a defect in the native loader**: it entered the kernel with the stack eight
   bytes off the ABI's alignment, and this step's `FXSAVE` into a local was the first thing in ten
   weeks to need 16-byte alignment there. Fixed in the loader the same day (TRACKER §3).
2. **Enable, and switch with `XSAVE`.** `FpArea`, the per-CPU enable with its read-back, and
   both switch sites. The vector probe is green on every lane, and its arm is red. The
   `XSAVEOPT` rule above is checked against the SDM. **Done 2026-10-30**: `xstate live
   xsaveopt with xcr0 0x3 on 4 of 4 cpus` on TCG `max` and KVM, `fxsave` on `qemu64`; the vector
   probe green on all three and on CI's QEMU 10.2.1 (`tools/boot-on-ci-emulator.sh`: four cells,
   181 gates each).
3. **Signal frames carry the state.**
   - First the `FXSAVE` format, which closes the filed defect on today's path. Then the `XSAVE`
     format.
   - The two calls, the validator and its fuzz target, and `AT_MINSIGSTKSZ`.
   - The signal probe is green and armed: a skipped restore turns it red.
   - A handler that edits the frame's state sees the edit stick.

   **Done 2026-10-30**, both formats at once rather than one after the other: `FP_READ` and
   `FP_WRITE` (methods 79, 80) on the fault object, which grew to three pages; the image placed
   64-aligned above the frame and marked as Linux marks one; the handler entered with the initial
   state; `rt_sigreturn` installing the frame's image after the kernel's check, or ending the
   program with `SIGSEGV` when the check refuses it; `AT_MINSIGSTKSZ` 2,048. The signal probe's
   handler also writes a new `xmm15` into the frame, and the interrupted code finds it -- on
   `XSAVEOPT` (BIOS, KVM) and `FXSAVE` (`qemu64`) alike. With the restore skipped: `32 of 32
   quadwords wrong`, the handler handed `xmm0 0x0`. **The check, against the instruction**: a
   harness that loaded every image the check accepts with the real `XRSTOR`/`FXRSTOR` on the build
   host ran 50,056,776 times in 121 s, clean, and with the check's `MXCSR` rule removed found the
   processor's `#GP` at once. That harness is **not in the tree**: it needs `unsafe`, and the fuzz
   crate's budget is zero by rule. The fuzz target in the tree (`fpstate`) is the pure half --
   every accepted image checked against the rules restated independently -- 26,871,526 runs in
   61 s, clean, and with the header rule removed it caught `accepted a dirty header`.
4. **AVX on.** `XCR0` `0x7` where offered. The vector probe checks the upper halves on CI `max`
   lanes and KVM.
5. **The v3 BusyBox lane.** Pinned and staged on `max` lanes: `BusyBox's sh ran`, the line run
   874 lost. The guides' three limits are rewritten.
6. **The cost, in the kernel.** Save-and-restore ticks per switch on the `cost` line, on every
   lane, and through KVM.
7. **The SR550.** Its `xstate` line, its `CR4` at entry, the v3 BusyBox, and the cost: the
   figures this draft could only take from another CPU.
8. **Documents.** `scheduler.md` §6 states the `XSAVE` design, `security.md` gets its line, and
   TRACKER's rows close.
