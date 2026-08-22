# RFC 0038: Vendoring the xHCI definitions

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | drivers |
| **Milestone** | Phase 2 (see docs/roadmap.md) |
| **Depends on** | RFC 0011 (interrupt handlers), RFC 0037 (a keyboard on real hardware), `docs/driver-model.md` |

---

## Summary

Bring the xHCI register, context and TRB definitions into this repository as
**vendored, adapted, attributed source** under Apache-2.0, taken from the
`xhci` crate — rather than deriving them from the specification a second time,
and rather than taking the crate as a dependency.

This RFC exists because the obvious version of that sentence — "vendor the
crate" — turned out not to be possible on inspection, and the reason is worth
writing down before anyone tries it again.

## Motivation

`docs/driver-model.md` item 8 is xHCI, and RFC 0037 has just stated its absence
plainly: a machine with no i8042 has no keyboard at all. Every modern laptop
without a legacy controller is that machine.

The bulk of an xHCI driver is not logic. It is **layout**: which register lives
at which offset, which bit in it means what, how a Transfer Request Block is
laid out, what an endpoint context contains and in what order. That work is
mechanical, voluminous, and unusually easy to get subtly wrong — a
one-bit-offset error produces a controller that appears to work and then
misbehaves under load rather than one that fails at boot.

It is also work that has already been done, carefully, in public, under a
license that permits taking it. Re-deriving it from the specification would be
re-doing settled work and inviting a class of error that the existing work has
already been through.

## What the inspection found

`xhci` 0.9.2, `rust-osdev/xhci`, `MIT OR Apache-2.0`, 5,759 lines of source.

The dual license is the ideal case for this project: it can be taken **purely
under Apache-2.0**, the same license Bhaskix already uses, so there is no
license mixing anywhere in the tree and no second license text to reconcile.

The obstacle is elsewhere. The crate has five dependencies —

| crate | what it is | lines |
|---|---|---|
| `accessor` | volatile MMIO access abstraction | 931 |
| `bit_field` | bit-range helpers | 839 |
| `paste` | proc-macro, token pasting | — |
| `num-traits` | numeric conversion traits | — |
| `num-derive` | proc-macro; pulls `syn`, `quote`, `proc-macro2` | — |

— and `syn` 1.0.109 alone is **44,682 lines**. Taking the crate whole means
vendoring on the order of **sixty thousand lines to obtain five thousand seven
hundred lines of xHCI knowledge**, most of it a Rust parser that runs at build
time, into a project whose dependency gate exists precisely so that this is a
decision rather than an accident.

They are not shallow uses that could be dropped: `accessor` appears 49 times
and `bit_field` 35 times across the crate.

## Design

### What is taken

The layouts, and the knowledge encoded in them:

- **Capability registers** — `CAPLENGTH`, `HCIVERSION`, `HCSPARAMS1..3`,
  `HCCPARAMS1`, `DBOFF`, `RTSOFF`.
- **Operational registers** — `USBCMD`, `USBSTS`, `PAGESIZE`, `CRCR`, `DCBAAP`,
  `CONFIG`, and the port register set.
- **Runtime registers** — the interrupter set: `IMAN`, `IMOD`, `ERSTSZ`,
  `ERSTBA`, `ERDP`.
- **Doorbells.**
- **Contexts** — slot and endpoint, input control.
- **TRBs** — the command, transfer and event forms actually used.

### What is not taken, and what replaces it

Each dependency is removed rather than vendored, and each has a local answer
that already exists or is trivial:

- **`accessor` → `kernel/src/mmio.rs`.** This one is not a compromise but an
  improvement: volatile access to device memory is something this kernel
  already owns and has rules about, and a driver reaching device memory through
  a *second* abstraction with its own opinions is exactly the drift the
  one-machine gate was written to stop elsewhere.
- **`bit_field` → shifts and masks written out.** A bit range is two
  operations. The dependency buys readability, and it costs 839 lines and a
  supply-chain entry.
- **`paste`, `num-derive`, `num-traits` → the code they generate, written
  out.** These exist to avoid repetition in the source. What they produce is
  mechanical; writing it out costs lines and buys the removal of a build-time
  Rust parser.

The result is a derivative work: same knowledge, different expression, and the
attribution says so.

### Where it lives, and how it is marked

A leaf crate, `third_party/xhci/`, at the same layer as `elf`, `net`, `fs` and
`rand` — `no_std`, depending on nothing, host-testable. Its directory says what
it is, so nobody has to infer provenance from a header.

Every file carries the upstream copyright notice and the Apache-2.0 identifier.
`NOTICE` gains an entry naming the project, the version taken, the license
taken under, and the fact that it is adapted rather than copied verbatim.

**`NOTICE` currently says Bhaskix vendors no third-party source at all.** That
sentence stops being true with this RFC, and changing it is part of the change
rather than a follow-up — a NOTICE that overstates a project's independence is
worse than one that names what it took.

### Why vendoring rather than depending

Both are supply chain; they fail differently.

A dependency is live. It updates, its own dependencies update, and the
reviewable unit is a version requirement rather than a body of code. For a
kernel, `docs/security.md` §1 treats that as attack surface, and
`tools/check-deps.py` refuses new ones by default — the kernel has **zero**
today, and the single allowed external crate is a fuzzing harness that is never
linked into it.

Vendored code is frozen. It is reviewed once, in full, at a known version, and
it changes only when somebody changes it here. That is a worse deal for
maintenance and a better one for a kernel, and it is the deal this project has
already chosen everywhere else.

## Alternatives considered

**Take `xhci` as a dependency.** Fastest, and it would be the first external
crate ever linked into this kernel, bringing five direct dependencies and a
proc-macro tree with it. Rejected on the numbers above.

**Vendor the crate and all five dependencies verbatim.** Preserves upstream
exactly and makes future updates mechanical. Rejected: sixty thousand lines,
most of them a Rust parser, in a repository whose review standard is that
somebody has actually read what is in it.

**Write the definitions from the specification.** No license question at all,
and it re-does careful public work while re-opening the class of error that
work has already been through. Rejected as a first choice; the specification
remains the authority when the vendored source and the hardware disagree.

**Use `crab-usb`, an MIT `no_std` xHCI implementation.** A larger take — the
driver as well as the definitions — and the driver half is the part that cannot
transfer: it assumes ambient kernel authority, not capabilities, domains and
`irq::claim`. Worth reading; not worth taking whole.

## Impact on existing design documents

- `NOTICE` — the "does not vendor" sentence changes, and an entry is added.
- `docs/driver-model.md` — item 8 gains a note on provenance.
- `tools/check-deps.py` — learns the new crate and its layer, so the dependency
  direction stays enforced rather than excepted.
- `docs/security.md` §1 — the supply-chain paragraph gains the distinction
  above, because "zero dependencies" stops being the whole story.

## Security implications

**Vendored code is code this project ships.** The Apache-2.0 grant covers the
right to use it; it does not make it correct. It is reviewed as our own,
budgeted as our own, and any `unsafe` in it counts against the crate's own
budget like any other.

The upstream crate contains 30 `unsafe` occurrences, all in the MMIO access
paths that `accessor` mediates — which is precisely the part being replaced by
this kernel's own module, so the vendored surface should carry **less**
`unsafe` than the original, not more.

A layout error here is a security bug, not merely a correctness one: a register
window sized wrong is a write outside the mapping, and a context field at the
wrong offset is a pointer the controller will follow.

### The bypass this device is, and the rules that bound it

**USB is the most dangerous device this project will have driven**, and not
because its parsing is hard. An xHCI controller is a **bus master**: it reads
and writes physical memory itself, on its own initiative, at addresses it was
handed. That path does not go through page tables. It does not go through
capabilities. A controller given a bad address does not fault — it succeeds,
into whatever is there. Every guarantee in `docs/architecture.md` is a statement
about what *code* can reach, and DMA is not code.

So the following are **requirements of the driver, gated, not intentions**.
They are written here, in the RFC that precedes the driver, because a mitigation
added afterwards is one somebody has to remember.

1. **No translation, no driver.** The driver refuses to initialise unless
   `iommu::present_for` answers true for its own bus/device/function. Not a
   warning, not a degraded mode: a refusal, reported in the boot log the way
   every other refusal in this kernel is. A machine with no IOMMU gets no USB,
   and that is the correct trade — the alternative is a device with unmediated
   access to all of memory in exchange for a keyboard.
2. **The window starts empty and stays nearly so.** `iommu::build_window`
   already begins with nothing mapped, which is the property this design leans
   on: the controller can reach exactly the rings and buffers it was given and
   nothing else — not the kernel, not another domain, not the rest of its own
   driver. Mappings are added per buffer and removed when done, so the reachable
   set is the working set rather than the lifetime union of it.
3. **Nothing is mapped that was not allocated for the device.** No mapping of a
   caller's buffer, ever. Data is copied into a device-owned buffer and out
   again. This costs a copy per transfer and removes a whole class of bug in
   which a pointer the driver did not audit becomes a pointer the controller
   follows.
4. **Interrupt remapping, or no MSI.** RFC 0012 built it; a device that can
   raise arbitrary vectors can inject interrupts the kernel attributes to
   something else. If remapping is unavailable the driver takes a pinned legacy
   line or nothing.
5. **Every descriptor is untrusted input.** Configuration, interface, endpoint
   and HID report descriptors are written by the device — which on a hostile USB
   stick means written by an attacker. They are length-prefixed, self-describing
   and nested, which is the exact shape that produces parser CVEs. They are
   parsed in a `forbid(unsafe_code)` leaf crate, every length checked against
   the buffer rather than believed, and **fuzzed before the driver ships**, as
   `elf`, `net`, `fs` and the package format already are. A descriptor parser
   that has not been fuzzed is not finished.
6. **The controller's own numbers are bounded before use.** Slot counts, port
   counts and context sizes come from a register, and a controller that reports
   nonsense — or is emulated by something hostile — must be refused rather than
   trusted into an allocation size or a loop bound.

### What this does not stop, said plainly

**A USB device that says it is a keyboard is a keyboard.** Nothing in this
design prevents a device from claiming the HID boot protocol and typing. That is
not an xHCI weakness, it is what a keyboard *is*, and the same is true of the
i8042 driver RFC 0037 added and of every operating system in existence.

What bounds it here is what bounds a person at the keyboard: keystrokes enter a
ring the shell reads, and the shell holds the capabilities it was given and no
others. There is no `root`, no ambient authority to escalate into, and typing
cannot reach what the shell could not already reach. That is a real bound and it
is not the same as prevention, so it is stated rather than implied.

The remaining exposure is that the driver runs in the nucleus, as the i8042's
does — so a bug in it is a bug with kernel authority. `docs/driver-model.md`
wants drivers in domains, and USB is the strongest argument yet for moving
console input out. That move is out of scope here and recorded as the debt it
is.

## Performance implications

None at this layer. Definitions compile to offsets.

## Testing plan

The layouts are pure data, so they are host-testable and must be tested on the
host: the size of each context, the offset of each register, and each bit range
round-tripping through its accessor.

**The test that matters most is the one that would catch a transcription slip**
— every register's offset asserted against the value the specification states,
written independently of the accessor that computes it, so that a wrong offset
fails rather than agreeing with itself.

## Unresolved questions

1. **How much of the crate to take now?** The definitions needed for a HID
   keyboard are a subset; taking the whole set costs review and takes work that
   may never run. Leaning toward the subset, with the boundary written down.
2. **Whether `crab-usb` should be read before the driver half is designed.**
   Reading it is free and informative; the decision is only whether its shape
   influences ours.
3. **Does the IOMMU requirement gate the whole driver**, or only the point at
   which it is handed a buffer address?

## Implementation plan

1. The crate, its license marking, the `NOTICE` entry, and the dependency gate
   updated — the paperwork first, so no code lands unattributed.
2. Capability and operational registers, adapted onto `mmio`, with offset tests.
3. Runtime registers and doorbells.
4. Contexts: slot, endpoint, input control.
5. TRBs: command, transfer, event, and the rings they sit in.
6. `docs/security.md` §1 and `docs/driver-model.md` updated in the same change
   that makes them true.

The driver itself — enumeration, slot assignment, endpoint configuration, the
HID boot protocol — is **not** in this RFC. This one ends with the definitions
in the tree, tested, and nothing using them yet.

**The six rules in §"Security implications" are binding on that driver**, and
the first of them — no translation, no driver — is the one to build first,
because a driver that works without it will not be given it later.
