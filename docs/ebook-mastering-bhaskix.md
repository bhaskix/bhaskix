# Mastering Bhaskix — scope

**Title:** *Mastering Bhaskix*
**Author:** Tarun Kumar Kushwaha
**Status:** Scoped, not written.

This document decides what the first book is *for*, what it may claim, and what
it must not. It is not an outline of chapters that would be nice to have; it is
the boundary that keeps the book true, because a book about a system that
overstates the system is worth less than no book.

---

## 1. The problem this book has, stated first

Most operating-system books are one of two things. Either they teach a *finished*
system — Linux, xv6, MINIX — where every design decision arrived long ago and the
reader learns the answer without the question. Or they are a build-your-own
tutorial that stops at a shell prompt, having never met the problems that start
after one.

Bhaskix is neither. It is a real system, mid-build, with **gaps its own
documents state in writing**: no libc, no self-hosting, and until 2026-08-22 it
had never booted on physical hardware. A book about it that pretended otherwise
would be caught by the repository it describes.

**So the gaps are the subject, not an embarrassment to route around.** This is a
book about how a serious system is actually built — including the parts where the
first answer was wrong, the measurement contradicted the reasoning, and the
record had to be corrected in place. That is a book almost nobody writes, because
almost nobody keeps the evidence. This project does: `TRACKER.md` is a dated
account of what was believed, what was measured, and where the two disagreed.

## 2. Who it is for

- **Systems programmers** who have read about capability systems and want to see
  one built, with the trade-offs visible rather than resolved offstage.
- **Students and self-taught engineers** past "hello world in a bootloader" and
  stuck at the point where a toy OS meets a real machine.
- **Engineers who care about how correctness is established**, not only about
  what the design is. The discipline is transferable even to readers who never
  write a line of kernel code.

**Not** for: end users. Nobody can use Bhaskix yet, and a book implying they can
would be lying on the first page.

## 3. What the book is

A worked account of building a capability-based operating system from nothing,
in Rust, using Bhaskix as the specimen — organised around **the method**, not
the module list.

The spine is one idea: **a claim you have not measured is a claim you do not
have.** Every chapter carries a design decision *and* the evidence that decided
it — a gate, a soak, a measurement, or a correction. Where the evidence is
absent, the chapter says so.

## 4. What the book is not

- **Not a reference manual.** `docs/` is that, and it is generated from the same
  source of truth the code is held to.
- **Not a tutorial to run Bhaskix.** It does not run anywhere that matters yet,
  and `SECURITY.md` says so.
- **Not a claim of production readiness**, novelty, or superiority. Where an
  idea is borrowed — seL4's capabilities, Limine's boot protocol, the xHCI
  layouts adapted under Apache-2.0 — the book names the source, as `NOTICE` and
  `CREDITS.md` do.

## 4a. Voice and language

**Indian English, written plainly.** The author is Indian, the project is
India-origin systems work, and the prose should read as what it is rather than
as something flattened into American technical writing. In practice:

- **Spelling and usage follow the British-derived conventions Indian English
  uses**, which the repository already uses: *behaviour*, *initialise*,
  *recognise*, *whilst* only where it is natural. Technical words keep their
  usual spelling: *program* for software, *programme* nowhere.
- **Numbers stay in the international form** — 1,00,000 is natural speech in
  India but a book with international readers should write 100,000. Lakh and
  crore appear only when quoting somebody.
- **No forced idiom in either direction.** Not Americanised, and equally not
  caricatured. "Do the needful" is not how engineers write; leave it out.

**Easy English, and this is the harder discipline.** The subject is difficult;
the sentences must not be. Rules that can be checked:

- **Short sentences.** If a sentence needs a second comma to survive, it is
  probably two sentences.
- **Common word over the impressive one.** *Use*, not *utilise*. *Enough*, not
  *sufficient*. *Before*, not *prior to*.
- **Define a term the first time it appears**, in the same sentence, in plain
  words — then use it freely afterwards.
- **Concrete before abstract.** Show the thing happening, then name the rule.
  Never the reverse.
- **Active voice, with somebody doing the doing.** "The kernel refuses the
  device", not "the device is refused".

### Examples must carry their weight

Every hard idea gets an example from ordinary life *before* the code. The
examples should be ones an Indian reader meets every day, because those are the
ones that need no explaining:

| Idea | The example |
|---|---|
| A capability | A **railway ticket**. It names your coach and berth. You can hand it to somebody else and it still works. Nobody at the door asks who you are — they only look at the ticket. |
| Ambient authority, and why `root` is refused | A **master key** that opens every room in the building. Convenient, until it is copied. |
| A domain | A **separate flat with its own door**, not a curtain in a shared hall. |
| The IOMMU | The **security guard at the society gate** who checks each delivery van and lets it into one block only — even though the van could physically drive anywhere. |
| A gate watched red | Pulling the **fire alarm on purpose** once, to be sure the bell actually rings. |

**And the standing caution applies to analogies too.** The project's rule is
that a familiar *name* must not imply a guarantee the system does not offer.
The same holds here: an analogy that flatters the design is worse than no
analogy. Where the railway ticket stops being true — a capability cannot be
photocopied, and a lost one is not replaceable at the counter — the book says so
in the same breath.

### What this does not license

Easy language is not vague language. The numbers stay exact, the refusals stay
refusals, and a measurement is quoted with its units and its date. A chapter
that reads smoothly and leaves the reader unable to say what was measured has
failed, however pleasant it was.

## 5. The shape

Four parts: **thirty-six numbered chapters, four interludes and a closing
chapter.** Each chapter ends with **"what was measured"** —
the gate, number or soak that made its claim real — and, where applicable,
**"what was wrong first"**.

**How to read the tables.** *Claims* is the one thing the chapter is allowed to
assert. *Carries it* is the evidence in this repository that makes the claim
checkable; a chapter whose evidence column is empty may not be written. *Status*
is one of **ready** (the evidence exists today), **partial** (writable, with a
gap the chapter must state), or **blocked** (the work is not done, and the
chapter waits).

The chapter list is a scoping decision and belongs here rather than in `book/`,
which holds only what has actually been written.

### Part I — The machine, and taking it

Entering from firmware, the handoff the project owns rather than borrows, paging,
and the first thing on a screen. Ends with the loader this project wrote to
replace the one it started with.

| # | Chapter | Claims | Carries it | Status |
|---|---|---|---|---|
| 1.1 | Where a computer begins | Firmware hands over in a defined state, and both UEFI and BIOS are that state | The two boot lanes, gated identically | ready |
| 1.2 | A handoff we own | `bhaskix_boot::Handoff` is the project's own structure; the bootloader is behind it, not through it | `tools/check-containment.sh` — only `boot/` may name Limine, checked on every build | ready |
| 1.3 | Addresses that are not memory | Paging, the direct map, and why a register window is not a page of RAM | `kernel/src/mmio.rs`, and the uncached-mapping rule | ready |
| 1.4 | Four levels, on purpose | Five-level paging was refused with written triggers, not overlooked | [RFC 0025](rfc/0025-four-level-paging-on-purpose.md); the boot-time refusal of a machine entered with LA57 live | ready |
| 1.5 | The first thing on a screen | Framebuffer and serial, and that a shared UART is not an absent one | The SR550's serial probe, wrong until 2026-08-22 — a correction with hardware behind it | ready |
| 1.6 | Writing our own loader | `bhaskixboot.efi` reached parity with the incumbent rather than replacing it on faith | [RFC 0028](rfc/0028-bhaskixboot.md); 74 gates green on both loaders plus the loader lane's own 23 | ready |
| 1.7 | KASLR, drawn and confirmed | The loader draws the slide and the kernel confirms it, because either alone is a claim | The boot gate that reads the slide back | ready |

*Interlude A — The first boot on metal.* One machine, one boot, observed on a
screen and **not captured**. What it falsified: the serial probe every gate had
passed. What it did not establish: anything about performance, because no report
was read. `partial`, and the chapter's honesty is the point of it.

### Part II — Authority

Capabilities, domains, and the argument that there is no `root`. Why containers
and virtual machines are the same primitive here. The IOMMU chapter belongs here
rather than in a drivers part, because a bus master is an authority question.

| # | Chapter | Claims | Carries it | Status |
|---|---|---|---|---|
| 2.1 | What a capability is | Authority is a thing you hold, and a stale reference is dead rather than wrong | `a_stale_reference_never_resolves_to_a_reused_entry`, watched red 2026-08-22 | **written** |
| 2.2 | No root, and what stands in for it | There is no ambient authority to inherit, so there is nothing for a tricked program to inherit | [RFC 0008](rfc/0008-syscall-and-ipc-shape.md); no user id in the nucleus | ready |
| 2.3 | A domain is a flat, not a curtain | Containers and virtual machines are one primitive, not two | `kernel/src/domain.rs`; the per-domain live-thread count that elects exactly one last thread | ready |
| 2.4 | Taking it back | Revocation is harder when authority is held, and this is what it costs | Generation counters; transitive revocation, gated | ready |
| 2.5 | Handing authority across a call | A capability can travel in a call and in a reply, and a failed delivery restores it | [RFC 0016](rfc/0016-capability-in-a-reply.md), [RFC 0022](rfc/0022-capability-in-a-call.md); the lender's death revoking what it lent | ready |
| 2.6 | There is no way up | A directory is a badged capability, and the ambient root is gone | `kernel/src/namespace.rs` **deleted**; the gate "a name outside the directory held is unreachable" | ready |
| 2.7 | A device that reads all of memory | A bus master is an authority question, and DMA is not code | [RFC 0012](rfc/0012-iommu.md); RFC 0041's rule 1 — a controller with no translation is refused by name, watched on every boot | ready |
| 2.8 | The rows that are not met | The threat table states what is unmitigated, and T11 prices what the adapter holds | [security.md](security.md) §1, with its status column | ready |

*Interlude B — The unsafe budget.* A number in `Cargo.toml` that a build refuses
to exceed, and what it is actually for: making growth **visible**, not making
`unsafe` impossible. Carries the 1622 → 2027 rise across RFC 0041's four steps in
one day, each increment itemised beside the number. `ready`.

### Part III — Time, and the things that go wrong in it

Scheduling, IPC, wait queues, and the intermittents. This is the part that could
not be written about a finished system, because a finished system has forgotten
how it found these.

| # | Chapter | Claims | Carries it | Status |
|---|---|---|---|---|
| 3.1 | Threads, and who owns one | A thread belongs to a CPU, and that ownership is what makes the runqueue a lock rather than a queue | M4-06, negative-tested by forcing every thread onto CPU 0 | ready |
| 3.2 | Rendezvous | Synchronous IPC, and why a reply is an obligation | [RFC 0008](rfc/0008-syscall-and-ipc-shape.md); the reply obligation a failed delivery was dropping | ready |
| 3.3 | Waiting, and being woken | Wait queues, deadlines, and a wake that arrives late | RFC 0019; the notification with a deadline honoured to a third of a millisecond | ready |
| 3.4 | The 494 ms spawn | Two branches that were never equivalent; a thread waiting on whatever deadline happened to be armed | The spawn-to-first-dispatch gate, bounded at 50 ms and watched red at 504 ms | ready |
| 3.5 | The domain that would not end | Two threads each concluding they were not the last; a window between checking and marking | 9 of 500 boots, every capture reading "still live 8 s on"; fixed by an atomic count, proven by 500 boots with zero | ready |
| 3.6 | A dying caller is a fact | `should_die` answered "false" when it meant "I do not know", and the answer was already in hand under the lock | `sched::waited`, and `Delivery::Dying` distinguished from `Abandoned`, 2026-08-23 | ready |
| 3.7 | Instruments that hid their subject | A worst-case wake with no name on it; a log read from its end; a guard table keyed on a line rather than a lock | Three corrections, 2026-08-21 to 2026-08-23 | ready |
| 3.8 | What a soak buys | Rates, not verdicts: 1 in 140, 1 in 330, "under 1 in 500" | `make soak`, and the runs behind each figure | ready |

*Interlude C — Watching a test go red.* Pulling the fire alarm once. Why a test
that has only ever passed is not evidence, and why "watched red" appears in
nearly every commit message in this repository. `ready`.

### Part IV — Reaching the world

Filesystem, network, the Linux personality as an adapter rather than a
reimplementation, packages, and input.

| # | Chapter | Claims | Carries it | Status |
|---|---|---|---|---|
| 4.1 | A filesystem in its own domain | The service holds the disk; the kernel holds nothing | [RFC 0015](rfc/0015-filesystem.md); `bin/fsd` | ready |
| 4.2 | A journal, interrupted on purpose | The claim is tested by cutting power at *every* write, not by argument | Host interruption at every write, plus once on a real disk | ready |
| 4.3 | A cache the journal governs | The page cache came last because the journal decides when a dirty page may go home | RFC 0015 step 6; a page lent read-only with nothing copied | ready |
| 4.4 | Frames, and a driver in a domain | virtio-net outside the kernel, and the three bugs the second driver cost | [RFC 0014](rfc/0014-driver-framework.md), [RFC 0018](rfc/0018-networking.md) | ready |
| 4.5 | A connection, both ways | TCP through rings the client's own domain owns | [RFC 0020](rfc/0020-tcp.md), [RFC 0022](rfc/0022-capability-in-a-call.md); both directions measured | ready |
| 4.6 | A second family, not a second stack | IPv6 as an address family, with the state machine untouched | [RFC 0029](rfc/0029-ipv6.md); both families measured on one boot | ready |
| 4.7 | Linux as an adapter | Compatibility above the services, never a reimplementation inside them; UID 0 is not authority here | [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md), [RFC 0032](rfc/0032-a-supervisor-interface.md); the ratchet that reads **0** Linux syscall numbers in the nucleus | ready |
| 4.8 | What a hosted process is | A record in ring 3 bound one-to-one to a domain; a pid invented outside the kernel | [RFC 0033](rfc/0033-what-a-hosted-process-is.md) | ready |
| 4.9 | Authority in one reviewable file | A package is a program plus what it asks for, and an over-ask is refused before a domain exists | [RFC 0030](rfc/0030-packages.md); the image a deterministic function of the manifests | ready |
| 4.10 | Somebody types | The i8042, and a keyboard that is state rather than events | [RFC 0037](rfc/0037-a-keyboard-on-real-hardware.md); `make test-keyboard` | ready |
| 4.11 | A controller you may not drive | An xHCI controller is refused unless it is caged, and the refusal is watched on a real controller | [RFC 0041](rfc/0041-a-usb-keyboard.md) steps 2–3; two controllers in the machine, one driven and one turned down by name | ready |
| 4.12 | Asking a device what it is | Descriptors over control transfers; a keyboard addressed, described, and its endpoint configured | RFC 0041 steps 4–6; the Device Context Index trap — endpoint 1 IN is index **3** — demonstrated live | ready |
| 4.13 | The keystroke | A report crosses from the device to the shell | RFC 0041 step 7 | **blocked** |

*Interlude D — Where a correction lives.* Why a wrong claim is corrected beside
itself rather than deleted, and what a changelog looks like when that rule is
kept for a year. Carries the vendored `root_hub_port_number` bug: a getter and
setter wrong together, pinned by a round-trip test that could never fail, found
by a controller refusing a command. `ready`.

### The closing chapter

**What is not true yet.** Not an appendix — a chapter, and the one most likely to
date. It states the gaps as the tracker states them: Phase 0's review criterion
unmet, one hardware boot with nothing captured, no libc, no self-hosting. If the
book has done its work, a reader reaching this chapter is not surprised by any of
it. `ready`, and rewritten for every edition.

## 6. What can be written now, and what cannot

**Restated 2026-08-23 against the chapter table**, because this section said
"USB beyond RFC 0041's definitions" is blocked and four of its steps landed the
next day. A summary that contradicts the plan it summarises is worse than none.

| | |
|---|---|
| **Writable now** | **All but one.** Thirty-five of the thirty-six numbered chapters, all four interludes, and the closing chapter. The per-chapter evidence in §5 is the authority; this row is only a count of it. |
| **Blocked on the work** | **One chapter: 4.13, the keystroke** — RFC 0041 step 7. Nothing has reached the shell over USB. |
| **Writable but must state a gap** | Interlude A: one boot on real hardware, observed on a screen and **not captured**, so no boot report was read and no self-test result from hardware is known. A performance chapter cannot be written at all; there is nothing to write it from. |
| **Must not be written yet** | Anything about libc or self-hosting. Any claim that Bhaskix runs a real workload. Any comparison against a system it has not been measured beside. |

The book tracks the repository. When a gap closes, a chapter can grow; until
then the chapter states the gap, which is the same rule the code lives under.

## 7. Production

- **Source:** Markdown in `book/`, one file per chapter, in this repository —
  so a change to the system and the change to the book that describes it can
  land together and be reviewed as one thing.
- **Licence:** the prose under a documentation licence chosen before the first
  chapter, not after; code excerpts stay Apache-2.0 as they are in the tree.
- **Figures:** diagrams as text where possible, so they diff.
- **Excerpts:** quoted from real files with their paths, never retyped — a
  listing that has drifted from the code is worse than no listing, and a gate
  should check it.

## 8. Open questions

1. **Does the book's build check its own excerpts against the tree?** It should;
   the cost is a script and the alternative is prose that rots silently.
2. **How much of `TRACKER.md` is quoted directly?** It is the strongest material
   in the project and also the least edited.
3. **What is the prose licence?** Apache-2.0 fits code and fits prose badly.
4. **Does the first edition wait for USB and real hardware**, or ship stating
   both as open? Waiting risks never; shipping risks a first edition that dates
   quickly. The project's own habit favours shipping with the gap stated.

## 9. What would make this book fail

Stated so it can be checked against later:

- Claiming maturity the tracker does not support.
- Becoming a reference manual, duplicating `docs/` and drifting from it.
- Losing the corrections — the chapters where the first answer was wrong are the
  ones a reader cannot get elsewhere.
- Vendor or tooling detail that dates within a release, in place of the
  reasoning, which does not.
