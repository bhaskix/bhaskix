# RFC 0000: <title>

| | |
|---|---|
| **Status** | Draft / Under review / Accepted / Rejected / Superseded by RFC-NNNN |
| **Author(s)** | |
| **Subsystem** | boot / arch / kernel / mm / sched / fs / net / drivers / libc / userspace / tools |
| **Milestone** | e.g. M3 (see docs/roadmap.md) |
| **Depends on** | RFC numbers, or design documents |

---

## Summary

One paragraph. What is being proposed, in terms someone who has not read the rest can understand.

## Motivation

What problem does this solve? Who has it? What happens if we do nothing?

Be concrete. "It would be cleaner" is not a motivation. "The current design cannot express X, which
milestone M5 requires" is.

## Design

The actual proposal. Include:

- Data structures and their invariants
- The interfaces other subsystems will see
- Concurrency: what locks, what rank, what runs in interrupt context
- Failure behaviour: out of memory, hostile input, hardware absent, concurrent teardown
- Where `unsafe` is needed and why it cannot be avoided

## Alternatives considered

**This section is required and is the most valuable part of the RFC.**

For each alternative: what it was, why it was rejected, and what would change our mind.

A rejected alternative recorded is worth more than the chosen one explained. It is what stops this
debate recurring in eighteen months when the contributors have turned over.

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| | | |

## Impact on existing design documents

Which of `docs/*.md` does this change? Quote the paragraph that becomes wrong.

If this RFC is accepted, updating those documents is part of the implementation, not a follow-up.

## Security implications

Reference [docs/security.md](../security.md) §1. Does this:

- Introduce new authority, or a new way to obtain existing authority?
- Change what is reachable without a capability?
- Add a parser for untrusted input? (If so: what is the fuzz target?)
- Move an item from "out of scope" to "in scope", or the reverse?

"None" is an acceptable answer where it is true, and a red flag where it is not.

## Performance implications

What gets faster, what gets slower, and what will you measure to know? A performance claim without a
benchmark is a hypothesis.

## Testing plan

- What can be tested on the **host**? (Prefer this — see docs/coding-style.md §8.)
- What requires QEMU?
- What requires real hardware, and how will contributors without it work on this?
- What is the fuzz target, if there is untrusted input?

## Unresolved questions

What is deliberately being left open, and who decides it later?

## Implementation plan

Rough sequence of PRs. This is not a schedule — it is a decomposition, so that others can help.

1.
2.
3.
