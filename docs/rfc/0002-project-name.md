# RFC 0002: Project name — Bhaskix

| | |
|---|---|
| **Status** | **Accepted** — 2026-08-02 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | project-wide |
| **Milestone** | Phase 0 |
| **Supersedes** | The working name *VyomOS* |

---

## Summary

The project is named **Bhaskix**.

Crate packages use the prefix `bhaskix-`, library and assembly symbols use `bhaskix_`.

## Motivation

*VyomOS* was a working name, adopted before the project had a public identity. Two problems surfaced
once it was time to make it real.

**The practical one:** the GitHub organisation handle `VyomOS` is held by an unrelated group
publishing networking tooling (`esp-frontend`, `vyom-tunnel-android`), registered February 2026. The
repository `vyomos/vyomos` was never created, but the handle is gone.

**The substantive one, which mattered more:** *vyom* (व्योम) means "sky". It is a pleasant word that
says nothing about the system. It is also a common noun in wide commercial use across India, so it
could never be owned, defended, or reliably found in a search.

A name is not decoration for a project that intends to be adopted by enterprises and governments. It
has to be distinctive enough to own and specific enough to mean something.

## Decision

**Bhaskix** — from *bhāskara* (भास्कर), "the light-maker", the sun.

It is also the name borne by two of India's great mathematician-astronomers:

- **Bhāskara I** (c. 600–680 CE) — the first person known to have written numbers in the
  Hindu-Arabic positional system with a circle for zero, and author of a rational approximation of
  the sine function accurate enough to remain in use for centuries.
- **Bhāskara II** (1114–1185) — the *Siddhānta Śiromaṇi*, containing results in differential
  calculus and a statement of what is now called Rolle's theorem, roughly five hundred years before
  Newton and Leibniz.

The `-ix` suffix places the project in the Unix lineage, exactly as **Minix** and **Linux** do. That
suffix is a century of systems-software convention compressed into two letters: it tells a systems
engineer what kind of thing this is before they read a word of documentation.

### Why this name and not a Sanskrit noun

The naming pattern that works for operating systems is a **coined word**, not a dictionary word.
"Linux" is Linus + the Unix `-x`; it is not a word in any language, which is precisely why Torvalds
could trademark it in 1997 when a squatter tried to claim it. "Minix", "Xenix", "IRIX", "Redox",
"Zircon" — all coined or borrowed from far enough away to be ownable.

A real noun in any language is already owned by hundreds of businesses, cannot be trademarked in the
software category without a fight, and loses every search-engine query it enters. *Bhaskix* is
coined: it inherits the meaning and the history of *bhāskara* while being a distinct, ownable
string.

### Properties

| Property | |
|---|---|
| Syllables | 2 — BHAS-kix |
| Pronunciation | Stable across languages; no sound unusual to English, Hindi, German, Japanese, or Portuguese speakers |
| Meaning | "Light-maker" (the sun), plus a mathematical lineage that is real and globally acknowledged |
| Lineage signal | `-ix` reads as Unix-family to any systems engineer |
| Ownable | Coined; not a dictionary word in any language |

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Keep VyomOS** | Handle taken; the name means "sky" and says nothing about the system; *vyom* is a common noun in commercial use and could not be owned. | — |
| **Shunya** (शून्य, zero) | Genuinely strong: zero is India's greatest contribution to computation, and "start from zero authority" describes the capability model exactly. Rejected because it is a common noun with existing commercial use — the same defect as *vyom*, however good the story. | We were willing to fight for a common noun. |
| **Meru** (the cosmic axis) | Good metaphor — the axis everything turns around is what a kernel is. Rejected: Meru Networks used the name commercially until Fortinet acquired them in 2015, so the search results are contested. | The dormant brand fully decays. |
| **Khagola** (खगोल, celestial sphere) | The only candidate free on GitHub, crates.io, and a domain simultaneously. Rejected on ergonomics: three syllables and a `kh-` onset that most non-Indian speakers will mispronounce on first contact. A name people are unsure how to say is a name they do not repeat. | Availability mattered more than pronounceability. |
| **Yantra / Medha / Dhruva and similar** | Dictionary words. Each is already used by many Indian companies; none is ownable or findable. | — |
| **Panini** (the grammarian, ancestor of BNF) | The best *intellectual* fit — Panini's Ashtadhyayi is the first formal generative grammar and a genuine ancestor of BNF. Rejected on search collision: a panini is a sandwich, and Panini is a large sticker company. Unwinnable. | — |

## Impact

| Area | Change |
|---|---|
| All documents in `docs/`, `README`, `AUTHORS`, `CONTRIBUTING`, `GOVERNANCE`, `TRACKER`, `LICENSE`, `NOTICE` | `VyomOS` → `Bhaskix` |
| Crate packages | `vyom-*` → `bhaskix-*` |
| Library names and assembly symbols | `vyom_*` → `bhaskix_*` |
| Phase 2 bootloader | `vyomboot.efi` → `bhaskixboot.efi` |
| Phase 3–4 daemons | `vyomd-*` → `bhaskixd-*` |
| Repository URL | To be set once the organisation is created |

Executed in one change across 36 files, with zero residual occurrences verified by grep. Doing this
at Phase 0 with no users, no contributors, and no published artifacts cost an afternoon. The same
change after Phase 1 would have touched every fork, article, and contributor.

## Security implications

None.

## Testing plan

A CI check asserts that the superseded name does not reappear in any tracked file.

## Unresolved questions

- **GitHub organisation handle** and **domain** are not yet registered. Availability was not
  independently confirmed before adopting the name; this must be checked and the handles claimed
  before the first public push. If `bhaskix` proves unavailable, the *project name* still stands —
  the handle can carry a suffix, as `rust-lang`, `golang`, and `nodejs` all do.
- **Trademark search and registration** in the software category. A governance action, not a
  technical one; required before the first release per [GOVERNANCE.md](../../GOVERNANCE.md) §5.
- The working directory on the author's machine is still named `vyomOS`. Cosmetic; rename at leisure.
