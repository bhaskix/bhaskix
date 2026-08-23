# Mastering Bhaskix

**Author:** Tarun Kumar Kushwaha
**Status:** Scoped, one chapter written.

A worked account of building a capability-based operating system from nothing,
in Rust, using [Bhaskix](../README.md) as the specimen — organised around the
method rather than the module list.

The spine is one idea: **a claim you have not measured is a claim you do not
have.** Every chapter carries a design decision *and* the evidence that decided
it — a gate, a soak, a measurement, or a correction. Where the evidence is
absent, the chapter says so instead of reaching.

---

## What exists today

**One chapter of thirty-six.** This directory holds what has actually been
written, and nothing else — a directory that listed chapters somebody intends to
write would be a table of contents pretending to be a book.

| Chapter | | |
|---|---|---|
| 2.1 | [What a capability is](02-authority/01-what-a-capability-is.md) | Authority is a thing you hold, and a stale reference is dead rather than wrong |

Everything else is planned and not started. The plan is in
[docs/ebook-mastering-bhaskix.md](../docs/ebook-mastering-bhaskix.md): four
parts, thirty-six chapters, four interludes and a closing chapter, each with the
claim it is allowed to make, the evidence in this repository that carries it, and
whether it can be written yet.

**All thirty-six can be written now**, as of 2026-08-23. The last one that could
not was 4.13, *The keystroke*, and RFC 0041 step 7 closed it the same day the
plan was written: a key typed at a USB keyboard reaches the shell.

That is a statement about *evidence*, not about difficulty. Every chapter has
something in this repository that makes its claim checkable; none of them has
been written.

## Why the book lives in this repository

So that a change to the system and the change to the book that describes it land
together and are reviewed as one thing. A book kept somewhere else drifts from
the system it describes, and drifts silently, which is the failure mode this
project spends most of its effort refusing everywhere else.

Excerpts are quoted from real files with their paths and **never retyped**. A
listing that has drifted from the code is worse than no listing.

## What this book is not

- **Not a reference manual.** [`docs/`](../docs/) is that.
- **Not a tutorial to run Bhaskix.** It does not run anywhere that matters yet,
  and [`SECURITY.md`](../SECURITY.md) says so plainly.
- **Not a claim of production readiness** or of novelty. Where an idea is
  borrowed — seL4's capabilities, the xHCI layouts adapted under Apache-2.0 —
  the book names the source, as [`NOTICE`](../NOTICE) and
  [`CREDITS.md`](../CREDITS.md) do.

## Layout

`NN-part/NN-chapter.md`, numbered so the directory sorts into reading order.
The numbering follows the plan, so a gap in this directory is a chapter not yet
written rather than a mistake.

## Licence

**Undecided, and deliberately so.** The scope document makes this open question
3: Apache-2.0 fits code and fits prose badly, and the choice is to be made
*before* the first chapter is published rather than after. Until it is settled,
the prose here is part of the repository and carries the repository's licence;
that is a placeholder and not a decision.
