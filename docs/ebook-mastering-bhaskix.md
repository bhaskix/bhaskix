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

Four parts. Each chapter ends with **"what was measured"** — the gate, number or
soak that made its claim real — and, where applicable, **"what was wrong first"**.

### Part I — The machine, and taking it

Entering from firmware, the handoff the project owns rather than borrows, paging,
and the first thing on a screen. Ends with the loader this project wrote to
replace the one it started with.

*Carries:* the boot gates; the loader at parity with the incumbent; and the first
boot on real hardware, which falsified an assumption every gate had passed.

### Part II — Authority

Capabilities, domains, and the argument that there is no `root`. Why containers
and virtual machines are the same primitive here. The IOMMU chapter belongs here
rather than in a drivers part, because a bus master is an authority question.

*Carries:* the security document's threat table, and the rule that a DMA-capable
device is refused unless it is caged.

### Part III — Time, and the things that go wrong in it

Scheduling, IPC, wait queues, and the intermittents: the 494 ms spawn, the
teardown race, the wake that was the boot thread all along. This is the part
that could not be written about a finished system, because a finished system has
forgotten how it found these.

*Carries:* soaks, breadcrumb rings, and instruments that had to be taught to name
their subject.

### Part IV — Reaching the world

Filesystem, network, the Linux personality as an adapter rather than a
reimplementation, packages, and input — the i8042 keyboard, and USB as far as it
has gone.

*Carries:* the fuzz campaigns, and the standing distinction between a familiar
*name* and a familiar *semantic*.

### Interludes

Short pieces between parts, each on one habit: watching a test go red on purpose;
the unsafe budget; why the tracker records what is *proven* rather than what
compiles; and how a correction is written where the wrong claim lived.

## 6. What can be written now, and what cannot

| | |
|---|---|
| **Writable now** | Parts I–III almost entirely; Part IV through packages and the i8042 keyboard. |
| **Blocked on the work** | USB beyond RFC 0041's definitions; anything about libc or self-hosting; performance on real hardware, of which there is one boot and no captured report. |
| **Must not be written yet** | Any claim that Bhaskix runs a real workload, or comparisons against systems it has not been measured beside. |

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
