# Contributing to Bhaskix

Every line of Bhaskix is developed in public. Contributions are welcome from anyone, anywhere, at any
level of experience.

> **Phase 0 note:** there is no bootable kernel yet. The highest-value contribution today is
> **critical review of the design documents** in [`docs/`](docs/) — especially the threat model in
> [docs/security.md](docs/security.md) §1 and the open decisions in
> [docs/architecture.md](docs/architecture.md) §8. A flaw found in a document costs an afternoon.
> The same flaw found in Phase 3 costs a year.

---

## Before you start

Read, in order:

1. [docs/vision.md](docs/vision.md) — what we are building and why
2. [docs/architecture.md](docs/architecture.md) — how it fits together
3. [docs/coding-style.md](docs/coding-style.md) — **required before your first PR**
4. [docs/roadmap.md](docs/roadmap.md) — what is currently being worked on

## Ways to contribute

| | |
|---|---|
| **Review a design document** | Open an issue with the specific paragraph and your objection. Disagreement is useful; vague approval is not. |
| **Write an RFC** | For any substantial subsystem. See below. |
| **Fix a `good-first-issue`** | These are real and kept stocked. If they run dry, that is a maintainer failure — say so in an issue. |
| **Improve tests** | Especially host-testable logic and fuzz targets. Undervalued and always welcome. |
| **Documentation** | Including translation. Contributors should not need English to read the architecture. |
| **Report a bug** | With a reproduction. QEMU command line, commit hash, and what you expected. |
| **Report a vulnerability** | **Privately.** See [docs/security.md](docs/security.md) §9. Never in a public issue. |

## The RFC process

Anything substantial gets a design discussion before it gets code. This is the single practice that
most distinguishes kernel projects that survive from those that get rewritten.

**An RFC is required for:** a new subsystem, a change to a documented invariant, a new dependency, a
syscall or ABI change, anything touching the capability system, or anything that raises a crate's
`unsafe` budget significantly.

**An RFC is not required for:** bug fixes, tests, documentation, or work that implements an already
accepted design.

1. Copy `docs/rfc/0000-template.md` to `docs/rfc/0000-my-idea.md`.
2. Open a PR. The PR *is* the discussion.
3. State the alternatives you rejected and why. **A rejected alternative recorded is worth more than
   the chosen one explained** — it stops the same debate recurring in a year.
4. Two maintainer approvals and a week of open comment merges it with a number assigned.
5. Implementation PRs reference the RFC.

Not sure whether your idea needs an RFC? Open an issue and ask. The answer is quick and free.

## Pull requests

- Branch from `main`. Rebase, do not merge, before submitting.
- One logical change per commit. See [docs/coding-style.md](docs/coding-style.md) §9 for the commit
  message format.
- **Sign off every commit** (`git commit -s`) — see DCO below.
- CI must be green: `cargo fmt --check`, `cargo clippy -D warnings`, host tests, QEMU tests,
  `unsafe`-budget check, dependency-cycle check.
- Every bug fix adds a regression test. If the bug was not testable, say what you changed to make it
  testable.
- Describe the design decision in the PR body, not the diff.

### What reviewers will focus on

In this order: **is the design right** → **is every `// SAFETY:` comment actually true** → **what
happens when this fails** → **is it tested at the lowest layer it could be** → **does it hold the
invariants in the design docs**. Formatting and naming are CI's job; reviewers spend their budget on
design.

If a reviewer and an author disagree and both are being reasonable, the design document was
ambiguous. The outcome of the argument belongs in the document, and updating it is part of the PR.

## Developer Certificate of Origin

Bhaskix uses the [DCO](https://developercertificate.org/) rather than a CLA. You keep your copyright;
you certify that you have the right to submit the work.

```sh
git commit -s -m "mm: fix buddy coalescing across zone boundary"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a working email. Pseudonymous contributions are accepted where the pseudonym
is stable and reachable.

## AI-assisted contributions

Permitted, with three conditions, and no stigma attached:

1. **You understand and can defend every line you submit.** "The tool wrote it" is not an answer to a
   review question, and it is not a defence when it turns out to be wrong.
2. **You have the right to submit it** — the DCO sign-off applies unchanged.
3. **No tool attribution enters the repository.** Bhaskix carries no model-vendor name and no
   assistant attribution in any file, commit message, tag, branch or release artifact. Commits carry
   `Signed-off-by:` (and `Fixes:` where one applies) and no other trailer — no co-authorship line, no
   generated-by line. See [docs/coding-style.md](docs/coding-style.md) §9.

**Condition 3 is enforced mechanically, not by review**, because it is the one that cannot be fixed
afterwards: a file can be edited, but a commit message, an author field, a tag or a branch name that
has reached a public push is permanent, mirrored and indexed.

- `tools/git-hooks/pre-commit` refuses staged content that carries an attribution.
- `tools/git-hooks/commit-msg` refuses the message and any co-authorship or generated-by trailer,
  whoever it names.
- `tools/check-containment.sh` — run by `make gates` and by CI — rescans the working tree, every
  commit message, every ref, and **every blob in history**, and additionally fails if the hooks are
  not installed.

Install the hooks once, with `make hooks`; `tools/setup-dev.sh` does it for you. The forbidden list
lives in one place, `tools/vendor-pattern.sh`, which also records what is deliberately *not* on it
and why.

In a kernel, the cost of a subtly wrong line is measured in weeks of someone else's debugging. That
standard is the same whoever or whatever typed it.

## Code of conduct

Be direct about code and kind about people. Technical disagreement is the point of the project;
personal attacks, harassment, and dismissiveness toward newcomers are not tolerated.

We are explicitly building a project that is accessible to contributors who are new to kernel
development. If someone asks a question that seems basic, answer it or point them at the document
that answers it. "Read the code" is not a review comment.

Report conduct issues privately to the maintainers. Enforcement is described in
[GOVERNANCE.md](GOVERNANCE.md).

## Getting help

- Open an issue with the `question` label. There is no such thing as a question too basic for a
  project at Phase 0.
- Discussion venues (chat, forum, mailing list) will be listed here once they exist.
