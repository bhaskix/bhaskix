# RFC 0042: Reading the boot report back

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-23, steps 1–3 implemented.** Written the same day as the second hardware boot, which failed for the same reason as the first. The record exists and the boot report no longer names its own address space; nothing can yet read it back, which is steps 4–6 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/console`, `services/console`, `user/shell` |
| **Milestone** | Phase 2. It gates nothing and unblocks **M1-17**, which has been open since Phase 0 |
| **Depends on** | [RFC 0013](0013-service-framework.md) (the console runs as a service), [RFC 0026](0026-telemetry-plane.md) (a ring this one deliberately differs from), [RFC 0037](0037-a-keyboard-on-real-hardware.md) and [RFC 0041](0041-a-usb-keyboard.md) (the machine can be typed at, which is what makes reading it back possible at all) |

---

## Summary

**The boot report is this project's primary instrument, and on real hardware
nobody can read it.** It is thousands of lines, a framebuffer holds about
twenty-five, and there is no way to scroll back. This RFC keeps what the kernel
prints in a bounded ring and lets somebody at the machine read it — subject to a
security question that turns out to be the hard part.

## Motivation

### Two hardware boots, one wall

Bhaskix has run on physical hardware twice. Both times the same thing stopped
the run being worth anything.

**2026-08-22.** The image booted on a Lenovo SR550 and the operator watched it on
the BMC's graphical console. `TRACKER.md` records the outcome exactly: *"Nothing
was captured: the kernel's output reached the framebuffer and not
serial-over-LAN, so no boot report was read and no self-test result is known."*

**2026-08-23.** The same machine, with a serial-over-LAN capture attached from
before the reset. Serial carried the firmware — `UEFI:DXE INIT`, the memory and
processor lines, the boot menu, `UEFI:POST END` — and then nothing. The kernel
booted, reached a shell, and answered the keyboard; the operator typed at it. The
boot report had scrolled off the screen by the time anyone looked, and **no
command can bring it back**: the shell has fourteen commands and none of them is
`dmesg`.

So the instrument this project relies on for every claim it makes is the one
thing that cannot be recovered from the machine the claims most need testing on.

### Why the obvious workarounds are not workarounds

**Serial.** The natural answer, and this machine is the counterexample the
project already owns. Its UART is shared with a service processor, and after
`UEFI:POST END` nothing the kernel writes reaches the far end. Commit `0087b87`
fixed one candidate cause — a loopback probe that called a shared port absent —
and **whether that fix works here is still unknown**, because the line that would
say so is printed to serial. *The diagnosis for a broken channel is written to
the broken channel.* That circularity is on its own enough reason for this RFC.

**A photograph of the screen.** It shows twenty-five lines of several thousand,
and not the ones that scrolled.

**Making the report shorter.** The report's length is not an accident; it is the
project's habit of stating what was measured. Cutting it to fit a screen would
destroy the instrument to fit the display.

## Design

### A ring in the kernel, filled by the same call that prints

Every line the kernel prints already goes through one place. That place also
appends to a fixed byte ring. Nothing else changes: no second formatting path, no
`log!` macro, no levels. **If it was printed, it is in the ring; if it was not, it
is not.** A log that can disagree with the console is a second source of truth.

### It fills once and stops, which is the opposite of the telemetry ring

[RFC 0026](0026-telemetry-plane.md)'s event rings are **drop-newest**: a running
system's newest events are the ones a reader has not seen, and losing the old
ones costs least.

A boot log wants the opposite end. **What scrolls away is the beginning** — the
handoff, the memory map, paging, KASLR, the IOMMU — and what is on screen is
already visible. So this ring **fills and then stops**, keeping the earliest
bytes, and counts what it refused. The count is printed, because a truncated log
that does not say it is truncated is worse than no log.

Sizing is a decision this RFC makes rather than defers: **64 KiB**, which is a
whole boot report today with room, and 64 KiB of static kernel memory is priced
on the boot line beside the other fixed tables.

### Reading it back is a capability, not a syscall

The console already runs as a service and already answers `WRITE` and `READ`. It
gains a third method, and a program that holds a capability to the console may
ask for the log the same way it asks to write. **The kernel gains no method and
no object** — the same bar RFC 0030 held itself to.

The shell gains one command. Its name should be the one a person coming from
Linux would guess, per the standing user-friendliness rule: **`dmesg`**. The name
is familiar; what it names is not a kernel ring buffer with priorities and
facilities, and the help text says so in one line.

## The hard part: the report names its own address space

**The boot report prints the KASLR slide.** `kaslr  slid {slide:#x} bytes from
{LINK_BASE:#018x}` — verified in `kernel/src/lib.rs`, not recalled. It also
prints device windows, the fixed tables' sizes, and other addresses.

Handing that to a ring 3 program hands it a **KASLR-defeating oracle**, in a
system whose whole argument is that a program can reach only what it holds. The
shell is trusted today; the point of a capability system is that this does not
have to stay true, and a facility that is only safe because of who happens to
call it is exactly the shape this project refuses everywhere else.

Three answers, and this RFC recommends the third:

1. **Redact on the way out.** Filter addresses as the log is read. Rejected: a
   filter that must recognise every address format is a parser with a security
   obligation, and it will be wrong the first time somebody prints an address in
   a new shape.
2. **A separate, stronger capability.** Reading the log needs a capability
   distinct from writing to the console, granted to nothing by default. Honest,
   and it makes `dmesg` unavailable on the machine where it is needed unless
   somebody remembers to grant it.
3. **Do not print the slide, and say where it went instead.** ✅ **Recommended.**
   The boot report's job is to say KASLR was applied and confirmed — which is a
   *yes or no*, plus the confirmation the loader and kernel agreed. The number
   itself is needed for debugging a crash, not for reading a report. Print
   `applied and confirmed` in the report and keep the value behind the same
   capability a debugger would need. Then the log carries nothing the shell may
   not already ask for, and answer 2's grant becomes an extra rather than a
   prerequisite.

**This is a change to what the boot report says**, and it is the reason this is
an RFC rather than a patch.

## Alternatives considered

**Write the boot report to disk.** The failures worth reading are the ones
*before* the filesystem service exists, which is most of the report. A log that
begins after the interesting part is not a log of the interesting part.

**Pause the report at each screenful.** Needs input, and input is one of the
things the report is reporting on. A machine whose keyboard did not come up would
stop at the first page for ever.

**Send it over the network.** Later than the filesystem, and the network is
itself one of the subsystems whose bring-up scrolls past.

**Keep only a summary.** The project's own habit is that a summary is what a
reader trusts when they cannot check; the report exists so they can check.

## Impact on existing design documents

- `docs/architecture.md` — the console service gains a method, and the list of
  what a console capability permits changes.
- `docs/security.md` §1 — a new row, or an amendment to the KASLR row: what the
  boot log exposes and to whom. This RFC's §"The hard part" is that row's
  argument.
- `TRACKER.md` — **M1-17's blocker changes shape.** It is not "a machine"
  (there is one) and not "a captured boot report" in the serial sense; it is
  "somebody could read what the machine printed".

## Security implications

Stated above and not repeated. The one sentence: **a boot log is a description of
the kernel's address space, and handing it to ring 3 is a capability decision
rather than a convenience.**

What this does not change: nothing new becomes reachable by DMA, no new kernel
object exists, and the ring is written only by the code that already writes to
the console.

## Performance implications

A byte copy per printed byte, into a ring, during boot. The boot report is
already dominated by the UART at 115200 baud — roughly 87 µs per character — so
the copy is not measurable beside it. It must be, and the boot-cost line already
in the report is where that is checked.

## Testing plan

**The ring on the host**, which is where the interesting cases are: filling
exactly, filling one byte short, filling one byte over, and the refused count
being right in each. Watched red by making it drop-newest, which passes a
carelessly written test and loses the beginning.

**A boot gate**: the report says how many bytes it kept and how many it refused,
and a boot whose report fits keeps all of it.

**The real test is a hardware boot**, and it is the first test in this project
whose subject is whether a person can find something out. It passes when somebody
at the SR550 types `dmesg`, reads the `serial` line that scrolled past, and can
say which of its three states this machine is in — a question open since
2026-08-22 that no amount of QEMU can answer.

## Unresolved questions

1. **Does the ring survive a panic?** A boot report that ends at a fault is the
   most valuable one there is, and reading it back needs the shell, which a panic
   has taken away. Possibly out of scope; possibly the whole point.
2. **Should the loader's own output join it?** `bhaskixboot.efi` prints before the
   kernel exists, and on the boot that hung on real hardware its output was the
   only evidence.
3. **One ring or two** — the boot report frozen, plus a rolling tail for a running
   system? Two is more useful and is a second mechanism to get right.
4. **Does `dmesg` mislead?** The standing rule is that a familiar name must not
   imply a guarantee the system does not offer. This has no priorities, no
   facilities, no timestamps and no persistence. The alternative is a name nobody
   guesses.

## Implementation plan

1. ✅ **Done 2026-08-23.** The ring: a fixed byte buffer, fill-once, with a
   refused count. Pure, host tested, watched red four ways including against
   drop-newest.
2. ✅ **Done 2026-08-23.** The console's print path appends to it, in
   `Console::write_str` — the one place all output already passes through. The
   boot report gains its kept and refused counts: `21570 bytes kept of 64 KiB,
   all of it`.
3. ✅ **Done 2026-08-23**, with one correction to this plan. The KASLR line says
   `applied and confirmed`. The value did **not** move behind a capability —
   there is no such capability yet — it moved behind `kaslr=show` on the command
   line, which is the same shape as `iommu=off` and available only to somebody
   who already controls the machine enough to pass it one.

   *And it broke a gate, which is the useful part.* `native-boot-test.sh`
   compares the slide the kernel reports against the one the **loader drew** —
   RFC 0028's proof that the two halves agree — and that check needs the value.
   That lane now asks for it. The weaker claim is asserted everywhere; the
   stronger one on the lane that can ask for the evidence.

   *Still owed from this step:* `security.md` has not gained its row.
4. The console service's third method, and the capability that permits it.
5. `dmesg` in the shell, with paging, and a help line that says what it is not.
6. A hardware boot on the SR550 that reads back the `serial` line — and, if it
   says what commit `0087b87` intended, closes a question open since the first
   physical boot this project ever did.
