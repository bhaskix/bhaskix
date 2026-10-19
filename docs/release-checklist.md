<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release checklist — `v0.1.0-preview`, 29 November 2026

The first release is a **developer preview** ([roadmap.md](roadmap.md#first-release--29-november-2026)):
an ISO a stranger can boot in QEMU, our own UEFI loader, the source, the RFC record, and the
[release note](release-notes.md). This checklist is how it gets out the door on its date.

**Decided by the project lead, 2026-10-19:**
- the version is **`0.1.0`** and the tag **`v0.1.0-preview`**;
- it is published as a **GitHub Release** on `bhaskix/bhaskix`;
- its binaries are **`bhaskix.iso`** and **`bhaskixboot.efi`**, each with a SHA-256 sum, **built by
  CI from the tagged commit** and never on a developer's machine;
- **the lead presses publish.** Everything up to a *draft* release is prepared and checked; making it
  public is outward-facing and cannot be unsaid, so it is the lead's act, on the day.

**The rule the roadmap set, repeated because it decides the day:** the release ships on 29 November
whether or not every criterion is met, and the note states what is not. A criterion that is
unmet on the day is a line in the release note, not a reason to slip.

Each step names who does it and the command that shows it is done. Tick it in the PR or commit
that does it, with the date.

---

## Now — by 26 October

- [ ] **R6: two reviewers asked** — *lead*. Two people who did not write the design documents, given
      [review-guide.md](review-guide.md) (about 3½ hours). Asked now, because six weeks is the whole
      window for a review to happen.
- [ ] **Trademark policy** — *lead*. [GOVERNANCE.md](../GOVERNANCE.md) §5 promises it "before the
      first release", and no document has it yet. A short policy page and its link from GOVERNANCE
      is enough; the decision is the lead's.
- [x] **The release note refreshed** — *2026-10-19*. Re-measured against TRACKER and that day's
      suite, and its three boot commands run from copies of the build; the next refresh is the week
      of the release.
- [x] **What a stranger sees first** — *2026-10-19*. Booted from a copied ISO on 2026-10-19, the
      kernel's last line said `M6 in progress`, the kernel shell's help promised "m6-05's user-mode
      shell", and the README and `make demo` told a newcomer to type `ps`, which the user-mode
      shell answers with "not a command". All four corrected, with a gate that fails when a document
      names a shell command the shell does not have.
- [ ] **The guides** — *engineering*, in `docs/guide/` and on the website: *Get started* by
      26 October; *The shell and packages* and *Linux programs* by 8 November. Every command in
      them is one that was run, and its output a transcript.
- [ ] **The website** — *engineering*. Under its own version control, its landing page brought up
      to date, and the guides rendered onto it. It says "planned" about the release until step 5
      of the day.
- [ ] **A release workflow** — *engineering*. `.github/workflows/release.yml`, run on a pushed tag
      `v*`:
  - build `make iso` and `boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi`;
  - **choose the ISO's Linux programs explicitly** (decided 2026-10-19): the Go `net/http` server
    in (`HTTPD_IN_IMAGE=1`), BusyBox out (`BUSYBOX_SRC=`). BusyBox is GPL-2.0, and shipping its
    binary would oblige publishing its source; without the explicit choice, whether it lands in the
    ISO depends on what the build machine happens to have installed;
  - ship Go's `LICENSE` beside the binaries, because the server carries Go's runtime;
  - **pin Limine to the tag `v8.7.0-binary`**, not the moving `v8.x-binary` branch that setup and CI
    follow, and record that tag in the release note;
  - write `SHA256SUMS` over both binaries;
  - create a **draft** GitHub Release holding them, with the release note as its body.

  **Rehearsed** on a throwaway tag (`v0.0.0-rehearsal`); the draft is then inspected and deleted,
  along with the tag.

## Two weeks before — 15 November: the freeze

- [ ] **Freeze** — *engineering*. From here on only fixes, tests and documents land. Work that
      changes a service's lifecycle — RFC 0092's listener close is the one in flight — either lands
      before the 15th with its suite green, or waits until after the release.
- [ ] **The defects table re-counted** against TRACKER §3, and any row closed since the refresh
      moved to the note's "closed" table.

## One week before — 22 November: the candidate

- [ ] **The version** — *engineering*. A commit sets `[workspace.package] version = "0.1.0"` in
      `Cargo.toml`, **and** `version = "0.1.0"` in `boot/bhaskixboot/Cargo.toml`, which is its own
      workspace — the loader reports itself in every boot report (`loader bhaskixboot 0.0.0` on
      2026-10-19). The programs under `user/` keep their own versions; the release is the tag and
      those two.
- [ ] **A full quiet-host `make test` green** on that commit, and **CI green** on it
      (`tools/ci-status.sh`).
- [ ] **From a clean clone**, which is R1's wording — in an empty directory:
      `git clone https://github.com/bhaskix/bhaskix && cd bhaskix && tools/setup-dev.sh && make test`.
      CI checks out clean too, but runs fewer lanes than `make test` (the release note's
      *Running it* says which).
- [ ] **The candidate tag rehearsed**: `v0.1.0-rc1` through the release workflow, its draft
      inspected and deleted. The ISO is booted from the draft's download, not from the build tree,
      and its sum checked with `sha256sum -c SHA256SUMS`.
- [ ] **Every guide's commands re-run** against that download, and any transcript that changed
      replaced with the new one.

## The day before — 28 November

- [ ] **Every dated figure in the release note re-measured** from that day's suite, with the date
      changed to it: the passing-check counts per lane, host tests, RFCs accepted of written, the
      HTTP lane's numbers, the open-defects count. The note's header says why this is not a
      formality.
- [ ] **R1–R7 restated in the note** as they stand that day — R6 especially, met or not.
- [ ] **TRACKER's release row and the roadmap's criteria table** say the same thing as the note.

## The day — 29 November

1. [ ] **CI green and a quiet-host `make test` green** on the release commit — *engineering*.
2. [ ] **Tag** — *engineering*: `git tag -s v0.1.0-preview` on the release commit, if a signing key
       for tags exists by then, otherwise an annotated tag, and push it. The tag is not a release
       signature; [GOVERNANCE.md](../GOVERNANCE.md) §5 keeps key custody a governance decision, and
       the note says the binaries are unsigned.
3. [ ] **The release workflow builds the draft** — the two binaries, `SHA256SUMS`, and the note as
       its body.
4. [ ] **The draft checked** — *engineering*:
   - both binaries download;
   - their sums match;
   - the ISO boots to the user-mode shell from the downloaded files by every command in the
     release note's *Running it* — BIOS, UEFI, and the native loader from an ESP;
   - the note renders, and every figure in it is dated the 28th or 29th.
5. [ ] **Published** — *lead*. The draft is reviewed and published.
6. [ ] **After** — *engineering*: TRACKER's release row and changelog record that it shipped, with
       the tag and the sums; the roadmap's criteria table gets its final column; README's status
       line names the release; the website's release panel links the published release, and its
       guides are rendered from the tag rather than from `main`.

---

## What this checklist does not do

It does not decide what is *in* the release — [roadmap.md](roadmap.md) did, on 2026-08-19, and the
note says what got there. It does not sign anything: signing is
[RFC 0091](rfc/0091-a-boot-its-owner-signed.md)'s, a draft with questions for the lead, and the
roadmap leaves it out of this release on purpose.
