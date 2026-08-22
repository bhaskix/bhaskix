# RFC 0037: A keyboard on real hardware

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | drivers |
| **Milestone** | M1-17 (see docs/roadmap.md) |
| **Depends on** | RFC 0011 (interrupt handlers), `docs/driver-model.md` |

---

## Summary

An i8042 (PS/2) keyboard driver, so that a machine booted from a USB stick can
be typed at.

Console **input** today is a UART and nothing else. `kernel/src/input.rs` says
so in its first line — *"the path from a UART with a byte to a thread that wants
one"* — and it is the only producer of console bytes in the system. Every test
this project runs types over a serial line, which is why the gap has never
shown up in a gate.

It shows up the first time anyone boots this on a laptop: the framebuffer will
carry the whole boot report, the shell will start, and there will be no way to
type a single character into it.

This RFC adds a second input source. It does **not** add USB; §"Alternatives"
says why that is a separate project rather than a larger version of this one.

## Motivation

`TRACKER.md` gap 2 has said the same thing since Phase 0: *nothing has ever
booted on physical hardware*. That gap is about to be closed on a real machine,
and when it is, this is what the machine will do — print beautifully, and
ignore the keyboard.

`docs/driver-model.md` already ranks the work: item 4 is *"PS/2 keyboard —
simple, enough for a kernel shell"*, item 8 is xHCI. This RFC is item 4, and it
is worth doing precisely because it is small.

A second reason, less obvious and more important: **console output is already
multi-sink and console input is not.** `console.rs` multiplexes writes to the
serial port and the framebuffer, and its header explains why — *"a user on real
hardware with no serial port sees a black screen"*. That exact argument applies
to input and was never followed through. This RFC finishes a symmetry the
system already believes in.

## Design

### One ring per source, and this is the whole design decision

The obvious implementation is to have the keyboard interrupt call
`input::push()`. It is wrong, and the module's own header says why before this
RFC was written:

> *One producer (the interrupt handler) and one consumer (whichever thread is
> reading). A lock would be the obvious choice and the wrong one … Disjoint
> indices make that impossible rather than unlikely.*

The ring is lock-free **because** it is single-producer. `push` reads `HEAD`
relaxed, stores a byte, then stores `HEAD + 1`. Two interrupt handlers doing
that concurrently — on different CPUs, which two claimed lines may well be —
both read the same head, both write the same slot, and both publish the same
index. One byte is lost and the other is published twice.

So the keyboard gets **its own ring**, with its own single producer, and the
*consumer* merges. `try_read` checks the UART ring and then the keyboard ring.
Each ring keeps exactly the invariant its correctness argument needs, no lock is
introduced anywhere, and the existing proof is not weakened by a word.

The merge order is fixed rather than fair — serial first — because the two are
never both busy in practice and a fixed order is one less thing that can starve.

### Claiming the line

Exactly as `input::install` already does it, because RFC 0011 made this
uniform: claim `Source::Line { gsi }` for the keyboard's IRQ 1 translated
through the firmware's overrides, bind a notification, and let the same service
thread wait on either.

The driver **drains before it acknowledges**, which is `docs/driver-model.md`
§2's rule for every driver and is not optional here: the i8042 raises its line
for one byte at a time and an edge raised while the source is masked is lost.

### Scancodes

Set 1, translated by a table, in a function that takes a byte and answers what
it produced: up to three bytes, because an arrow key is an escape sequence and a
ring of bytes cannot be handed a key. It touches no hardware and holds no state
beyond the modifiers, so it is host-testable — which `docs/coding-style.md` asks
for, and which a table this dull will otherwise never be checked at all.

**Set 1 is arranged for, not assumed.** A keyboard actually speaks set 2; it is
the controller's translation bit that makes it arrive as set 1, and firmware is
free to leave that bit either way — UEFI on a machine that never touched the
legacy port has no reason to have set it. So the driver sets it explicitly when
it configures the controller. Left to chance the failure mode is not a dead
keyboard, which would at least be obvious, but a keyboard where every key types
the wrong character.

Handled: the printable set, `Enter`, `Backspace`, `Tab`, `Space`, both `Shift`
keys as modifiers, `CapsLock` as a toggle, and `Ctrl` for `^C`/`^D` because a
shell without them is not a shell. Break codes (bit 7 set) update modifier state
and produce nothing. The `0xE0` prefix is consumed and the following byte
mapped only for the arrow keys; everything else it introduces is dropped
deliberately rather than mistranslated into a printable character.

### A machine with no i8042

Not every machine has one, and probing a controller that is not there must not
hang. Presence is decided by the controller self-test — command `0xAA` to port
`0x64`, expect `0x55` from `0x60` — under a **bounded** spin on the status
port, with the driver reporting absence rather than waiting for it.

The ACPI `IAPC_BOOT_ARCH` flag in the FADT is the more correct answer and is
deliberately *not* used: this kernel's ACPI parses MADT, MCFG and DMAR and has
no FADT reader, and adding one to answer a single bit is a larger change than
the driver it would guard. Recorded as follow-up work rather than pretended
away.

Failure is survivable and said out loud, in the same voice as the serial line's:
a machine with no keyboard controller boots, reports that it has none, and is
still reachable over serial.

## Alternatives considered

**Extend the existing ring to two producers.** Rejected above: it trades a
lock-free invariant with a written proof for a race that appears under exactly
the conditions nobody tests — two lines busy at once.

**A lock around the shared ring.** Rejected for the reason the module already
gives: the producer is an interrupt handler that can land between a consumer's
acquire and release.

**Poll the controller from the shell instead of taking an interrupt.** Simpler,
and it discards the thing this kernel is good at. It would also spin a CPU that
`docs/scheduler.md` §7 has just been taught to leave alone.

**Do USB first, since that is what modern machines have.** Rejected on size, and
the size is not close. xHCI needs PCIe enumeration, a 64-bit MMIO register file,
command/event/transfer rings, TRB construction, device slots and endpoint
contexts, `ADDRESS_DEVICE`, descriptor parsing, and only then the HID boot
protocol on top. `docs/driver-model.md` calls it *"the largest attack surface
here"* and ranks it eighth for that reason. It is a milestone, not a step, and
it gets its own RFC.

The honest consequence, stated so nobody is surprised at a keyboard that does
nothing: **after this RFC a USB keyboard still will not work.** Many laptops
present their built-in keyboard through the embedded controller's i8042
emulation and will; some recent thin machines have no i8042 at all and will not.

## Impact on existing design documents

- `docs/driver-model.md` — item 4 of the driver list becomes built rather than
  planned.
- `kernel/src/input.rs` — its header says "the path from a UART"; it becomes the
  path from a UART *or a keyboard*, and the single-producer argument gains the
  sentence that explains why there are two rings rather than one.
- `TRACKER.md` — a keyboard gap is not currently stated anywhere. It should have
  been, and it is added in the same change whether or not this RFC is built.

## Security implications

An input source is an authority source: whatever it produces is read by the
shell as if a person typed it. Two properties keep that bounded.

**No new privilege.** The keyboard produces bytes into a ring the shell already
reads. It gains no capability, names no domain, and can invoke nothing.

**No new reach across sources.** Each producer writes only its own ring and
publishes only its own index, so a fault in one cannot corrupt the other's
bytes — which is a security argument for the two-ring design and not merely a
correctness one.

The driver runs in the nucleus, as the UART's does, and that is a debt this
RFC records rather than settles: `docs/driver-model.md` wants drivers in
domains. Moving console input out is the same move for both sources and should
be made once, for both, rather than half-made here.

## Performance implications

One interrupt per key event, a table lookup, and a ring store. Not measurable
against anything, and it removes nothing from a hot path.

The bounded probe costs a fixed number of I/O reads once at boot, on a machine
that may not answer them.

## Testing plan

**The translation table, on the host.** A pure function from byte to
`Option<u8>` — every printable key, both shifts, caps-lock toggling, break codes
producing nothing, `0xE0` swallowing its successor. This is where the table's
mistakes will be, and it needs no machine.

**The driver, in QEMU.** QEMU has an i8042, so this is gateable before any real
hardware is involved: drive the monitor's `sendkey`, type a command at the
shell, and require the shell to answer it. That is an end-to-end gate on the
whole path — interrupt claimed, line drained, byte translated, ring published,
shell woken — and it fails if any link is missing.

**Watched red before it is believed**, as every gate in this tree is: by
refusing the claim, and by breaking the translation table, each seen to fail on
purpose.

**Real hardware remains untested until a machine exists.** This RFC does not
close M1-17 and does not claim to; it removes one specific reason the machine
would be useless when it arrives.

## Unresolved questions

1. **Which real machines actually expose an i8042?** Unanswerable from here and
   answerable in one boot on the target laptop. The driver's absence report is
   written to make that boot conclusive rather than confusing.
2. **Should console input move to a domain**, with both sources, before or after
   USB? The driver model wants it; nothing forces the order.
3. **Does the FADT reader get written for this**, or wait until something else
   needs the table too?

## Implementation plan

1. The scancode table and its translation function, with host tests. No
   hardware, no interrupts.
2. The second ring, and `try_read`/`pending` merging two sources, with the
   single-producer argument rewritten to cover both.
3. The controller probe, bounded, with its absence report.
4. The claim, the bind, and the drain-before-acknowledge service path.
5. The QEMU `sendkey` gate, watched red twice.
6. `docs/driver-model.md`, `input.rs`'s header and `TRACKER.md` updated in the
   same change that makes them true.
