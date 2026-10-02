# RFC 0088: A clock a process reads itself

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-10-02 — proposed, not built.** Nothing here is implemented; the acceptance call, and whether to build it at all, is the project lead's. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bhaskix-personality`, `bin/linuxd`), kernel (boot loader for hosted programs, `time`) |
| **Milestone** | Phase 2 — after [RFC 0086](0086-the-motivating-workload.md), whose measurements motivate it |
| **Depends on** | [RFC 0005](0005-linux-abi-compatibility.md) (the initial process image), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (no Linux numbers interpreted in the nucleus), [RFC 0032](0032-a-supervisor-interface.md) (the adapter in ring 3), [RFC 0019](0019-time-and-timers.md) (decision TM1: reading time is not a capability) |

---

## Summary

Give every hosted Linux process a one-page vDSO — a tiny ELF image, mapped
read-execute and named to the process by `AT_SYSINFO_EHDR` — whose one
function, `__vdso_clock_gettime`, reads the cycle counter and turns it into a
`timespec` **in the caller's own ring 3**, with exactly the arithmetic
`bin/linuxd` uses to answer `clock_gettime` today. A process that reads its
clock then makes no call. The page is offered only on a machine whose CPUs'
counters are measured at boot to agree; anywhere else the auxv entry is
omitted and every reader falls back to the system call, as now.

## Motivation

RFC 0086 measured the Go server that is its gate, and the measurement points
at one call. Thirty seconds, 7,106 responses, 2026-10-02:

| call | per response |
|---|---|
| `clock_gettime` (228) | **11.50** |
| `read` (0) | 1.32 |
| `write` (1) | 1.00 |
| everything else | under 1.2 together |

**About four calls in five are the runtime reading its clock.** Each is a full
round trip to the adapter — the boot's own figure for one is a floor of about
161,000 cycles and a mean of about 695,000 under TCG — plus a `COPY_OUT`
crossing of sixteen bytes; those crossings are 11.5 of the 12.85 outward
crossings per response in RFC 0086's copy record. The cause is read, not
guessed: go 1.27.1's `nanotime1` (`runtime/sys_linux_amd64.s`) calls
`vdsoClockgettimeSym` when the auxv named a vDSO and falls back to the
`syscall` instruction when it did not, and nothing here names one
(`personality::stack::auxv` builds seven entries, none of them
`AT_SYSINFO_EHDR`).

**If nothing is done**, every hosted program that tells the time pays an
adapter round trip to do it, and the adapter — one thread — spends most of its
answers on a question whose answer the caller's own CPU already holds. It is
not a correctness problem; RFC 0086's gate passes. It is the largest single
cost the measurement found, and it lands on the one component every hosted
program shares.

## Design

### The image

`bhaskix_personality::vdso::image(hertz) -> [u8; 4096]`, pure and host-tested,
builds one page:

- an ELF64 header, `ET_DYN`, two program headers — one `PT_LOAD` covering the
  page, one `PT_DYNAMIC`;
- a dynamic table with `DT_HASH`, `DT_STRTAB`, `DT_SYMTAB`, `DT_VERSYM` and
  `DT_VERDEF`, and a version definition naming **`LINUX_2.6`**;
- one symbol, `__vdso_clock_gettime`, `STT_FUNC`, `STB_GLOBAL`, version
  `LINUX_2.6`;
- the function's code.

**The version table is not optional, and that was read rather than assumed.**
go 1.27.1's `vdsoInitFromSysinfoEhdr` treats an image without one as valid and
sets `versym` to nil — and then `vdsoFindVersion` walks `info.verdef` without a
nil check (`runtime/vdso_linux.go`, read 2026-10-02). An image without
`DT_VERDEF` would therefore not be ignored; it would fault the runtime at
start-up. The other two symbols Go looks for, `__vdso_gettimeofday` and
`__vdso_getrandom`, are left out: Go falls back to the system call for each,
and neither appears in RFC 0086's counts.

### The function

```text
__vdso_clock_gettime(clock rdi, timespec* rsi):
  clock is MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE or BOOTTIME,
  or REALTIME or REALTIME_COARSE?               -- personality::clock::plan's set
    no  -> mov $228, %eax; syscall; ret         -- the adapter answers, as today
  rdtsc; combine edx:eax into one 64-bit count
  mul by 1,000,000,000 (128-bit product)
  div by HERTZ (an immediate baked in at build)  -- floor, exactly clock::nanos
  store seconds and nanoseconds at rsi; xor %eax,%eax; ret
```

**The same arithmetic as the adapter, not an approximation of it.** A
multiply-and-shift is the usual fast form, and it rounds differently from
`clock::nanos`'s exact 128-bit division. A process that read one clock through
the page and the next through the system call could then see time go
backwards by a nanosecond or two. Using the same `mul` / `div` keeps the two
paths bit-identical for the same counter value; `div` is the slower
instruction and still thousands of times cheaper than a round trip.
`CLOCK_REALTIME` is the Unix epoch plus the time since boot, as
`personality/src/clock.rs` already answers it — the machine believes it is
early 1970, and says the same thing on both paths.

`HERTZ` is the measured counter rate `bin/linuxd` already holds. There is **no
data page**: nothing changes the rate or the epoch after boot (no NTP, no
RTC), so the constants live in the code. A design that ever adjusts time would
need a data page and a sequence count, and is named below as what would
reopen this.

### Mapping it

Both loaders build the initial stack through `personality::stack::Builder`:
the kernel's for boot programs (`ring3_go`, the HTTP lane's server) and
`bin/linuxd`'s for `execve`. Each maps the page read-execute at a free
address in the new process, the way `bin/linuxd` maps a `clone` trampoline
page today, and the builder gains an optional eighth auxv pair,
`AT_SYSINFO_EHDR` (33). One page per process; nothing shared between
processes, so nothing about one process's page is visible to another.

### When it is offered: the CPUs must agree

`kernel/src/time.rs` says so plainly: *"No cross-socket TSC synchronisation
check. Every reading here is compared only against another reading from the
same CPU. That assumption must be revisited before any timestamp crosses a
CPU boundary."* Today it never does — every `clock_gettime` is answered by the
adapter's one thread. A vDSO reads the counter **on whichever CPU the caller
is on**, so a thread that migrates could see time run backwards if the CPUs'
counters disagree.

So the kernel measures before it offers. At boot, with every CPU up, it takes
a cross-CPU counter comparison (each application processor reads the counter
against a value the bootstrap processor publishes, both ways, and keeps the
worst disagreement), prints it in the boot report, and **offers the page only
when the counters are invariant (`msr::features().invariant_tsc`) and the
worst disagreement is below a bound** the step that builds it sets from
measurement. Otherwise `AT_SYSINFO_EHDR` is left out and every program uses
the system call — today's behaviour, unchanged. The SR550 has one socket
(a Xeon Silver 4110, sixteen CPUs online), so it tests sixteen CPUs agreeing
rather than two sockets; the check is run there before the RFC asks to be
accepted, and a multi-socket machine stays untested until one is available.

### Failure behaviour

- Counters disagree, or not invariant: no auxv entry; nothing changes.
- A clock the page does not serve: the page makes the system call itself, so
  the answer is the adapter's, `EINVAL` included.
- A program that ignores the auxv: unaffected.
- A program that parses the image differently from Go: the image follows the
  System V layout Linux's own vDSO does; a parser that rejects it falls back
  as Go does when the auxv names nothing. Which other runtimes read it — musl's
  static BusyBox among them — is checked in the step that builds it, not
  asserted here.

### `unsafe`

None in `bhaskix-personality`, which forbids it: the image is bytes built by
safe code. The loaders write a page they already write today (the kernel's
`ring3_go` image copy; `bin/linuxd`'s `COPY_OUT`), so no new `unsafe` is
expected beyond what mapping one more page costs in each.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Answer `clock_gettime` in the nucleus | RFC 0031's measure is the count of Linux numbers interpreted in the nucleus, and it reads **0**; this would make it 1, for the busiest call there is. | Never on its own; only if RFC 0031's frame were reopened. |
| A data page the adapter updates, read with a sequence count (Linux's own design) | It solves a problem this machine does not have: nothing adjusts the rate or the epoch after boot. It adds a writer, a page shared with every process, and a retry loop. | Wall time arrives — an RTC driver, NTP, `settimeofday` — and time can change under a reader. |
| Multiply-and-shift instead of `div` | Rounds differently from the adapter's exact division, so mixing the two paths can go backwards by a nanosecond. | Measurement shows `div` matters next to everything else a call to the page costs. |
| Cache the time in the adapter and answer faster | Still a round trip and a crossing per call; the cost is the crossing, not the arithmetic. | — |
| Leave it | RFC 0086's gate passes without it; correctness does not need this. | The lead decides throughput is not worth a page per process and a boot check. |

## Impact on existing design documents

- `personality/src/clock.rs`'s module note — *"A process here has no vDSO"*
  (in substance) becomes conditional on the boot check.
- `kernel/src/time.rs`'s note quoted above is answered by the check, and is
  updated to say what was measured.
- RFC 0005 §"The initial process image" gains `AT_SYSINFO_EHDR`.
- `security.md` §1: see below.

## Security implications

- **No new authority.** The page carries code and two constants; a process
  that maps it gains no capability and can reach nothing it could not before.
- **No new timing source.** `CR4.TSD` is clear, so ring 3 can already execute
  `rdtsc` — `bin/linuxd` does — and a hosted process can today. That is an
  accepted decision, not an accident: TM1 (RFC 0019) made reading time
  deliberately not a capability, because being *woken* is the scarce thing. The page
  removes a round trip; it does not grant precision a process lacked.
- **No new parser of untrusted input.** The image is built here and parsed by
  the hosted program; nothing in the system parses it.
- **One more mapped page per process**, read-execute and never writable, as
  the `clone` trampoline page is. Which envelope its frame is charged to
  follows whatever the loader's other pages do (RFC 0082); step 3 states it.

## Performance implications

Expected: the 11.5 `clock_gettime` calls per response leave the adapter, and
the server's calls per response fall from about 14.6 toward 3. **Expected is
not measured**, and nothing about throughput is claimed until the HTTP lane
measures it; the lane's existing lines — calls by number, copies per response,
latency — are what the measurement is. Cost: one page per hosted process, and
a cross-CPU comparison at boot whose duration step 2 measures.

## Testing plan

- **Host:** the image parsed by a test that follows go 1.27.1's lookup
  exactly — `DT_HASH`, the version walk, the symbol — and finds the function
  at its offset; the same image without `DT_VERDEF` rejected by the test, so
  the trap above is pinned. The code's arithmetic checked against
  `clock::nanos` over edge values (zero, one second, a day at 3 GHz) by running
  the same 128-bit computation.
- **QEMU:** an assembly probe that reads `AT_SYSINFO_EHDR`, calls the function
  for each clock the page serves and for one it does not, and compares against
  the system call; the HTTP lane's calls-by-number line showing number 228
  near zero; every existing lane unchanged.
- **Hardware:** the cross-CPU comparison read off the SR550, all sixteen
  CPUs.
- **Watched failing:** the probe with a deliberately wrong `HERTZ`; a boot
  with the bound forced to zero, which must omit the entry and still pass.

## Unresolved questions

1. **The bound on cross-CPU disagreement.** What the comparison reads under
   TCG, under KVM and on the SR550 decides it; the step that builds the check
   reports those numbers before the bound is chosen.
2. **musl's reader.** Whether a static musl BusyBox takes the page, and
   whether its lookup matches Go's, is read in its source in the building step.
3. **Where in the address space.** The `clone` trampoline's search for a free
   page is the obvious model; whether the kernel's boot loader and
   `bin/linuxd` should share one placement rule is a detail for step 3.

## Implementation plan

1. **The image**, in `bhaskix-personality`, host-tested as above, with the
   go-shaped lookup in the tests.
2. **The boot check**: the cross-CPU counter comparison and its report line;
   measured under TCG, KVM and on the SR550.
3. **The mapping**: both loaders map the page and the builder offers
   `AT_SYSINFO_EHDR`, only when step 2 says the counters agree.
4. **The probe and the measurement**: the assembly probe as a gate, and the
   HTTP lane's figures before and after, recorded here and in RFC 0086.
