<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reviewing the Bhaskix design documents

This is the packet for **criterion R6**: *the design documents reviewed by two
people who did not write them*. It is Phase 0's own exit criterion and it has
been unmet since Phase 0 — recorded openly in
[roadmap.md](roadmap.md#first-release--29-november-2026) rather than quietly
dropped.

If you are considering reviewing, this page is written to let you decide in five
minutes.

---

## The ask, honestly sized

**About 3½ hours of reading**, and however long you want to spend writing down
what you found.

That is the *design documents* — fourteen files, roughly 44,000 words. It is
**not** the whole repository, and this matters: `TRACKER.md` is 283,000 words and
the RFCs another 222,000. Those are **evidence you may sample**, not required
reading. Anyone who tells you R6 means reading all of it is quoting a number
five times too large.

| | Words | ~Minutes |
|---|---|---|
| [vision.md](vision.md) | 696 | 3 |
| [architecture.md](architecture.md) | 5,768 | 28 |
| [security.md](security.md) | 11,159 | 55 |
| [roadmap.md](roadmap.md) | 6,035 | 30 |
| [scheduler.md](scheduler.md) | 3,645 | 18 |
| [memory.md](memory.md) | 3,522 | 17 |
| [driver-model.md](driver-model.md) | 2,632 | 13 |
| [coding-style.md](coding-style.md) | 2,684 | 13 |
| [ai-native.md](ai-native.md) | 1,968 | 9 |
| [prior-art.md](prior-art.md) | 1,160 | 5 |
| [repo-layout.md](repo-layout.md) | 720 | 3 |
| [nightly-features.md](nightly-features.md) | 448 | 2 |
| [../README.md](../README.md) | 2,561 | 12 |
| [../GOVERNANCE.md](../GOVERNANCE.md) | 863 | 4 |

*(Measured 2026-08-30. Re-measure if these look stale.)*

**A partial review is worth having.** If you only have an hour, read
`vision.md`, `architecture.md` and `security.md` §1 and say so in your findings.
Two partial reviews from people who were honest about their scope beat one
review that claims more than it did.

---

## Who can do it

Anyone who did not write these documents. You do **not** need to be a kernel
engineer — several of the most useful questions are the ones a careful outsider
asks:

- an OS or systems engineer, on the mechanisms;
- a security engineer, on [security.md](security.md) and whether the threat
  model is honest;
- a technical writer or editor, on whether the documents say what they mean;
- anyone at all, on whether a stranger reading `README.md` would be **misled**
  about what works.

You do not need to agree with the design. R6 does not ask for endorsement.

---

## Suggested order

1. **[vision.md](vision.md)** (3 min) — what this is for.
2. **[README.md](../README.md)** (12 min) — the claims a newcomer meets first.
   *Ask: would this mislead me about what works?*
3. **[architecture.md](architecture.md)** (28 min) — the mechanisms, and §8's
   settled architecture questions.
4. **[security.md](security.md)** (55 min) — the threat model. §1's gap list is
   the part most worth your scepticism.
5. **The subsystem documents** — scheduler, memory, driver-model — as your
   interest takes you.
6. **[roadmap.md](roadmap.md)** (30 min) — scope, milestones, and the release
   criteria including this one.

---

## What we are asking you to look for

Not style. Not typos. These five:

1. **Is a claim stated as fact that the evidence does not support?** The
   project's own rule is that until a gate proves something, no document may
   state or imply that it works. Where does a document break its own rule?
2. **Is a gap hidden, softened, or buried?** Gaps are supposed to be as plain as
   the features. Find one that is not.
3. **Do two documents contradict each other?** They are maintained by hand and
   have drifted before.
4. **Is the threat model honest** about what is mitigated versus merely named?
5. **Would a newcomer be misled** about the state of this project by any
   document here?

**Checking a claim is meant to be cheap.** Most rest on a gate you can run:
`make test` runs what CI runs, and the boot lanes print their assertions. If a
document says something is proven and you cannot find the proof, that is
exactly the finding we want.

---

## How to record what you find

1. Copy [review/0000-template.md](review/0000-template.md) to
   `docs/review/NNNN-your-name.md`.
2. Fill it in — including what you **did not** read.
3. Open a pull request.

Findings are kept in the repository, not resolved privately. A review that
found nothing is also a result, and should say what was examined.

**Two independent reviews, not one negotiated one.** Please do not read the
other reviewer's findings before writing your own.

---

## What this criterion is not

It is not a code review, not an audit, and not a security certification. It is
two people outside the project reading what it says about itself and reporting
where that is wrong, unsupported, or misleading.

If it is still unmet on release day, the release ships and says so.
