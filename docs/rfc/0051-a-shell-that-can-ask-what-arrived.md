# RFC 0051: a shell that can ask what arrived

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-27** — proposed, built and accepted the same day. A ring 3 shell could not answer *"is the keyboard working?"*, because the counters live in the nucleus and it holds capabilities rather than kernel statistics: `input` there answered **`not a command`**. It answers now, through `method::INPUT_STATS` on the `Console` and `console::STATS` in the service protocol, needing `Rights::READ` — the right a holder must already have to *take* a typed byte, so it counts without consuming and grants nothing new. **What acceptance does not claim.** *(1)* It is a **count, not a notice**: somebody must ask. The instrument that would answer without being asked — a line on first contact — was built and taken back out, because it prints between the prompt and the shell's echo of that key and splits the line being typed. *(2)* **It has not run on the machine that asked the question.** The SR550 boot of this date predates it; the counters were confirmed on QEMU in both placements and on both shells, and hardware has not seen this. *(3)* The counters are **saturating `u32` pairs**, so a boot that somehow typed four billion bytes would read as a working keyboard gone quiet — bounded and stated rather than discovered. *(4)* Unresolved questions 1 and 2 stay open: a dropped byte is reported and nothing reacts to it, and the service asks the nucleus on every call |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0013](0013-relocatable-services.md) (the console service), [RFC 0042](0042-a-boot-report-that-can-be-read-back.md) (the shape this follows) |

---

## Summary

Add `INPUT_STATS` to the nucleus `Console` object and `STATS` to the console
service's protocol, so a ring 3 shell can ask how much input arrived and from
which source.

## Motivation

**A question a machine could not answer about itself.** The SR550's boot report
says `keyboard i8042 present, irq 1 -> vector 0xfc` and then never says whether a
key followed. On 2026-08-27 its keyboard appeared dead and nothing in the system
could distinguish the three states that matter: the i8042 is not delivering; it
is delivering and the decoder is swallowing; it works and something else is
wrong.

The counters to tell them apart exist — `input::per_source` and
`keyboard::scancodes` — and **every way of reading them needs the keyboard that
is in doubt**:

- The boot report's `input by src` line prints before anybody can type.
- The kernel shell's `input` command needs a `shell=kernel` boot *and* a
  keyboard.
- That machine cannot be typed at over serial at all: the BMC redirects COM2,
  which this kernel uses for output only.
- The **ring 3 shell**, which is what it actually boots to, holds capabilities
  rather than kernel statistics — a gate written against `input` there failed
  with `input: not a command`, correctly.

**A one-shot notice was tried and is the wrong answer.** Printing *"first key
seen"* when the first scancode arrives answers the question with nothing read
back, and it lands **between the prompt and the shell's echo of that key** —
splitting the line the person is typing. It broke the keyboard lane immediately.
An instrument that corrupts the session it is explaining is not an instrument.

So the shell should be able to **ask**.

## Design

**Nucleus.** `method::INPUT_STATS` = 70 on a `Console` capability, requiring
`Rights::READ` — the right `TAKE` and `POLL` already need, because this reads the
input side. No holder gains anything it could not already observe by draining the
input it is entitled to; it gains the ability to observe it *without* consuming
it.

Six numbers, **one reply word per call**, chosen by `arg0`:

| `arg0` | high half | low half |
|---|---|---|
| `0` | serial received | serial dropped |
| `1` | keyboard received | keyboard dropped |
| `2` | i8042 scancodes | input interrupts |

**One word and not four, because a system call returns one.** `Outcome` carries
a status and a value; the four-word `args` array belongs to IPC messages, not to
`INVOKE` returns. This draft said "three reply words" until the code was written
against it and the type said otherwise. `RECORD` beside this already has its
caller walk an offset for exactly this reason, so the shape is the established
one rather than a new one. Out-of-range asks read **zero** rather than failing:
a reader that meets a fourth pair it does not know about should get "nothing
here", not a refusal to special-case.

**Saturating at `u32::MAX`, and said here rather than discovered**: these are
boot-lifetime counters and four billion bytes is not a session, but a counter
that wrapped would read as a working keyboard that had gone quiet, which is the
one reading this must never produce.

**Scancodes are reported beside bytes because they are different facts.** A key
release and a modifier are scancodes that emit no byte. `scancodes` moving while
`keyboard received` stays at zero says the i8042 is delivering and the decoder is
swallowing — a fault invisible in either number alone, and the reason this is not
one figure.

**Service.** `console::STATS` = 5 in the protocol the console service answers.
`bin/consoled` holds a `Console` with `Rights::ALL`, so it needs no new grant: it
invokes the nucleus method and passes the three words back. It interprets
nothing — the same posture as `RECORD`, which hands back bytes it does not read.

**Shell.** An `input` command in `bin/shell`, named as the kernel shell's already
is, so a person who learns one knows the other.

## Alternatives considered

**Give the shell a `Console` capability directly.** It would need `READ` on the
nucleus object, which is the authority to *take* a typed byte — and the console
service is the thing that owns reading input. Two readers of one input path is
the bug RFC 0013 avoided by putting the service in front of it.

**Print the statistics in the boot report only.** Already done, and it is a
baseline rather than an answer: it prints before anyone can type.

**A one-shot notice on first contact.** Rejected above, by measurement.

## Impact on existing design documents

None contradicted. `docs/driver-model.md` §2's account of the input path is
unchanged: this reads counters, and takes nothing.

## Security implications

**No new authority.** `INPUT_STATS` needs `Rights::READ`, which is what a holder
must already have to take a byte. A holder that could read the input can now also
count it.

**It is an observation channel and worth saying so.** A domain holding a console
`READ` can watch how much has been typed without consuming it. That is a weak
side channel between a person at a keyboard and a service — and the same holder
could already learn strictly more by draining the input itself, which is why this
does not widen anything. It would matter if a `READ` were ever handed to
something not trusted with the input, and that would be the wrong grant with or
without this method.

## Performance implications

Three atomic loads behind one capability invocation. It is not on any path that
runs without a person asking.

## Testing plan

1. **A boot gate on the ring 3 shell lane**: type `input` at it and require the
   line, with the serial column non-zero — the shell test types over serial, so
   that column *must* have moved, and a gate that accepted zero would pass on a
   machine where nothing worked.
2. **The keyboard lane**: type `input` after the keys and require the keyboard
   column to be non-zero. That is the assertion this RFC exists for, and it is
   the one that could not be written before.
3. Watched red by returning zeros from the service.

## Unresolved questions

1. **Should `dropped` be a fault rather than a number?** A dropped byte is input
   the machine was told about and lost. It is reported and nothing reacts to it.
2. **Should the console service cache these?** It asks the nucleus on every call
   today. Nothing needs it to be cheaper yet, and a cache would be a second
   source of truth for a number whose whole value is being the first.

## Implementation plan

1. `bhaskix_abi::method::INPUT_STATS` (70) and `bhaskix_abi::console::STATS` (5).
   ✅ **Done 2026-08-27.**
2. The nucleus arm: resolve `Console`, require `READ`, pack, reply. ✅ **Done**,
   one word per call as corrected above.
3. The service answers `STATS`. ✅ **Done, in both placements** — `bin/consoled`
   asks the nucleus three times and puts all three in one reply; the in-nucleus
   placement reads the counters directly, because there the service *is* the
   thing keeping them. The aggregation lives in the service so that no caller
   has to ask three times.
4. `bin/shell` grows `input`, and `help` lists it. ✅ **Done.** It prints:

       bhaskix$ input
         serial    29 bytes, 0 dropped
         keyboard  0 bytes from 0 i8042 scancodes, 0 dropped
         interrupts 6 delivered the above

5. The two gates, watched red. ✅ **Done.** The user-mode shell lane types
   `input` and requires the **serial** column to be non-zero — that harness types
   every command over the serial line, so those bytes are counted by the time it
   runs, and a gate accepting zero would pass on a machine where nothing worked.
   The keyboard lane types `input` after its keys and requires the **keyboard**
   column to be non-zero, which is the assertion this RFC exists for. Both were
   watched red by returning zeros from the service, and both failed.

   One correction the writing of them earned: `shell-test.sh`'s `await` matches
   with `grep -F`, so a pattern with a character class is matched *literally* and
   never found. The count cannot be written down — it changes whenever a command
   is added to the list — so the assertion is a `grep -E` placed after the line
   that proves the whole list ran.
