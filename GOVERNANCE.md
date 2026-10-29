# Bhaskix — Governance

*Status: initial. This document changes as the project grows, and every change to it is itself a
public decision.*

"Transparent governance" is a core principle in [docs/vision.md](docs/vision.md). This document says
who decides what, how, and how that changes over time.

---

## 1. Current structure — honest about the stage

Bhaskix is at Phase 0 with one author. Pretending otherwise would be theatre.

**Project lead:** Tarun Kumar Kushwaha — original author. Currently holds final say on technical
direction and on the open decisions in [docs/architecture.md](docs/architecture.md) §8.

This is a **benevolent-dictator model by necessity, not by preference**, and it is designed to
dissolve. The transition conditions are written down in §4 so that they are a commitment rather than
a hope.

## 2. How decisions are made

| Decision | Who | How |
|---|---|---|
| Bug fixes, tests, docs | Any maintainer | Review + merge |
| Implementation within an accepted design | Any maintainer | Review + merge |
| New subsystem, invariant change, ABI change, new dependency | Maintainers | RFC, two approvals, one week of open comment |
| Architecture direction, open decisions A1–A5 | Project lead, after RFC | RFC with a public rationale, including rejected alternatives |
| Governance changes, license | Project lead + all maintainers | Public discussion, minimum two weeks |
| Security response | Security contacts | Privately until disclosure, then public post-mortem |

**Everything except an unpatched vulnerability happens in public.** Design discussions in private
channels do not become policy; if a decision was reached in a call, it gets written up in the RFC
before it counts.

### Rejected alternatives are recorded

Every accepted RFC states what was considered and rejected, and why. This is not ceremony. It is what
prevents the same argument recurring every eighteen months as contributors turn over, and it is how
someone joining in year three understands why the system looks the way it does.

## 3. Becoming a maintainer

There is no application. The path is:

1. Sustained, quality contribution over time — code, review, documentation, or testing. Review counts
   fully; a good reviewer is rarer than a good author.
2. Demonstrated judgement about what *not* to build, and willingness to say so.
3. Nomination by an existing maintainer, public discussion, no sustained objection.

Maintainers own a subsystem. Maintainership is not a status; it is an obligation to review other
people's work in that area.

A maintainer who is inactive for six months moves to emeritus, with no stigma and an open door back.
Life happens; the project should not depend on anyone's continued availability.

## 4. Dissolving the single point of control

Success in [docs/vision.md](docs/vision.md) includes: *"The project survives the departure of any
single contributor, including its founder."* That is a governance requirement, and here is how it is
met.

**When the project reaches five active maintainers from at least three organisations or independent
positions**, governance moves to a **technical steering committee**:

- Maintainers elect the TSC annually.
- The TSC decides architecture direction by majority, not by any one person.
- The project lead becomes one voice on it.
- The lead retains no veto and no special commit rights.

Until then, the lead commits to:

- Never merging their own non-trivial change without another maintainer's review.
- Publishing the reasoning for every direction-setting decision, including the ones they lose.
- Treating a sustained technical objection from a maintainer as blocking, not advisory.

## 5. Trademark, naming, and forks

- **The code is open. Forks are legitimate.** Anyone may fork Bhaskix for any reason, and a fork is
  not a hostile act.
- **The name is not the code.** "Bhaskix" identifies builds that come from this project so that users
  can tell what they are running. A fork should be named differently. Trademark policy will be
  formalised before the first release.
- **Nobody ships a release-signing key in a repository** — and since 2026-10-29 `make gates`
  refuses a tracked private key or `*.secret` file, or a file ending in a committed public key.
- **Key custody** is a governance decision with technical consequences
  ([docs/security.md](docs/security.md) §3). ~~It will be documented before any signed release
  exists.~~ Decided by the project lead on 2026-10-29
  ([RFC 0091](docs/rfc/0091-a-boot-its-owner-signed.md), questions 3–7):
  - **Who.** The project lead alone holds the release keys. When there is a second maintainer, a
    sealed backup is placed with them, and custody shared k-of-n is considered then.
  - **Where.** On a machine that has never been networked, its disk encrypted, and in two encrypted
    backups on two offline media kept in two places. **Never in a cloud key service**: the key that
    decides what boots on an owner's machine does not sit in a third country's data centre.
  - **What.** An offline CA, whose certificate owners enrol in their firmware's `db`, with a signing
    leaf beneath it that signs each loader — so a leaf is replaced without any owner enrolling
    again — and a boot-set key whose public half is compiled into each loader release and rotated
    with it.
  - **Loss.** Revoked through `dbx`; refusing an older signed release waits for a rollback counter
    (security.md, T7).
  - **Owners' keys**, for a boot they sign themselves, live outside every checkout. The published
    test key in `tests/keys/` protects nothing, is named in red wherever it verified a boot, and is
    refused by the release recipe.
  - **The procedure** is [docs/release-keys.md](docs/release-keys.md).

  This custody text was amended under §8 on 2026-10-29. RFC 0091 had proposed it publicly from
  2026-10-12, and the lead agreed to it.

## 6. Funding and independence

- Bhaskix accepts sponsorship. **Sponsorship does not buy technical direction.** All sponsors are
  disclosed publicly, including the amount if the sponsor permits.
- No contributor is required to assign copyright. There is no CLA — the DCO is sufficient
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
- If a company employs maintainers, that is disclosed. A single employer holding a majority of
  maintainer seats is a governance risk, and the TSC composition rule in §4 exists partly to bound it.

## 7. Conduct enforcement

Reports go privately to the project lead, or — if the report concerns the lead — to any maintainer.

Responses, in escalating order: private discussion, public warning, temporary suspension from project
spaces, permanent removal. Enforcement actions above a private discussion are recorded publicly in
aggregate (what happened, what was done — not the identity of the reporter).

Maintainers are held to a higher standard than contributors, not a lower one.

## 8. Amending this document

Changes require public discussion of at least two weeks and agreement from the project lead and all
maintainers. The reasoning goes in the PR, and the PR stays in the history.
