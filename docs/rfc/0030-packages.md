# RFC 0030: Packages — authority made reviewable

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/shell`, `bin/sup`), fs, tools, new leaf crate `pkg/` |
| **Milestone** | Phase 2 — the "package management and image building" bullet, one of the two left on the phase's list |
| **Depends on** | [RFC 0015](0015-filesystem.md)/[RFC 0016](0016-writable-filesystem.md) (the VFS and the journalled writable filesystem a package is installed onto), [RFC 0017](0017-process-management.md) (`START`, reaping, and the supervisor pattern the runner follows), [RFC 0008](0008-syscall-and-ipc-shape.md) (all authority arrives as a capability argument), `driver-model.md` §5 (the manifest-as-reviewable-authority principle this RFC generalises) |

---

## Summary

**A package is a program plus the authority it asks for, in one reviewable file.** On this
system a binary without capability grants does nothing — so the unit of distribution must
carry both, and the manifest is the half a reviewer reads. `driver-model.md` §5 already
states the principle for drivers: *"the manifest is the reviewable summary of a driver's
authority — a reviewer can see what a driver can reach without reading the driver."* This
RFC makes that the shape of every installable thing. Two halves, one format: at **build
time**, the boot image stops being a fourteen-line `cp` list in the Makefile and becomes a
deterministic function of the package set — same inputs, byte-identical image, asserted
rather than hoped. At **run time**, a package is installed onto the writable filesystem,
its programs are started with **exactly the grants its manifest requested and the granter
held** — an over-ask refused whole, RFC 0022's discipline — and removed without a trace.
The design claim, tested by building it: **packaging adds nothing to the kernel.** Every
call the installer and runner need existed before this RFC. What does *not* arrive, each
with a written trigger: network fetching, signatures, dependency resolution, upgrades, and
install-time scripts.

## Motivation

**The bullet is one of Phase 2's last two, and the image is currently nobody's design.**
`build/initrd.tar` is assembled by a hand-maintained `cp` list; the authority each service
holds is wired in kernel code, program by program; and "installed" has no definition at
all — a program either shipped in the image or does not exist. Phase 2's exit criterion
says *"Bhaskix self-hosts its own userspace utilities"*, and self-hosting starts with being
able to say what a utility **is**: its bytes, its authority, its presence or absence, as
one auditable object. Meanwhile the capability model makes classical package managers
wrong by construction: a postinst script that "just runs" is ambient authority through the
back door, and a package format that lists files but not grants documents the half that
matters less. Doing nothing leaves the Makefile as the de facto package manager and the
kernel source as the de facto grants database — both unreviewable in exactly the way
`driver-model.md` §5 was written to prevent.

## Design

### The package: one archive, manifest first

A package is a **ustar archive** — the format the initrd already uses and the machine
already parses, the same documented subset, sorted names, zero mtime, so identical inputs
give identical bytes. Extension `.bpk`. The first member is `manifest`; everything after it
is payload, addressed by the manifest. Nothing in the archive is executed, interpreted, or
trusted at install time: the installer copies what the manifest names and refuses
everything else, droppings included.

### The manifest: a line grammar, not a config language

Line-oriented `key value` text with section headers, parsed by a zero-`unsafe` parser in
the new leaf crate `pkg/` — `no_std`, host-tested, fuzzed like every parser beside it. Not
TOML: a `no_std` TOML parser is a bug surface bought for aesthetics, and a grammar of
ninety lines is greppable by every tool that exists. The vocabulary:

```
package hello
version 0.1.0

program bin/hello
  entry hertz
  cap console
  cap notification
  cap memory pages=1

file bin/hello sha256=af13...9e length=18432
```

`package`/`version` name the unit. Each `program` section names a payload binary, its
entry convention, and its **capability requests** — by kind, from the vocabulary the ABI
actually has (`console`, `endpoint <service>`, `memory pages=N`, `notification`,
`timer`), each one line, so a diff of authority is a diff of lines. **Step 2's
correction, recorded where the claim stood: the fourteen real programs taught the
vocabulary seven more things.** `serve <name>` joined beside `endpoint <name>` because
answering and asking are different powers and a manifest that conflated them would review
as less than it grants; `device-registers`, `dma-window`, `interrupt`, `domain-control`
and `directory` joined because the drivers, the supervisor and the shell genuinely hold
those authorities and a vocabulary that could not spell them would have forced either a
lie or a blank; and `pages=` became optional on `memory` because the supervisor's
child-image object is sized by the granter to the program it stages — a fixed number
there would be stale on every program change. The vocabulary remains closed; it is
simply no longer smaller than the truth. Each `file` line
carries the payload's SHA-256 and length. **The hash is honest about what it is**: inside
an unsigned archive it detects corruption, not tampering — an adversary who rewrites the
payload rewrites the hash beside it. It is content identity, and it becomes load-bearing
the day Phase 3's secure-update chain signs the manifest, because the signature over these
lines is then a signature over everything. SHA-256 lands in `pkg/` as pure arithmetic,
implemented against the published FIPS 180-4 test vectors — stated here because the spec
is being written from reference material, and the vectors are what make that safe.

### Image building: the image becomes a function

A `packages/` directory in-tree holds one manifest per program the image carries — the
fourteen current programs get theirs in this RFC, which is also the moment their authority
becomes *written down* instead of implicit in kernel code. A host tool `mkimage` (a `std`
binary inside `pkg/`, the `mkfs` pattern) assembles `build/initrd.tar` from the package
set plus the static files: deterministic, sorted, byte-identical across runs — **gated**,
two assemblies compared, and the migration itself gated by comparing the new image's
member list against the old rule's before the `cp` list retires. The kernel's bring-up
does not change in this RFC: it reads the same paths it read yesterday. Whether the
*grants* the kernel wires migrate out of code and into these manifests is open question 1,
and it is the biggest thing this RFC deliberately does not decide.

### Install, run, remove: the writable filesystem earns its journal

**Step 3's verdict, recorded over the design it tested.** The write path exists and the
whole install arc is gated: `pkg install hello.bpk` at a live prompt verifies with the
same parser the host tools use, installs payload-first/record-last, lists, and refuses a
second install off the record it wrote. The `dir` protocol grew `CREATE_AT`,
`MAKE_DIRECTORY_AT`, `WRITE_FROM`, `REMOVE_AT` and `LIST_AT` — all service-defined; the
kernel gained **no method and no object**: `DRAIN`, `FILL`'s mirror, already existed, and
"packaging adds nothing to the kernel" held at the letter of code paths. What did change
kernel-side, stated: two grant lines (the shell's writable `/pkg` handle, minted from the
handle `bin/fsd` reports after ensuring `/pkg` exists — a journalled create exercised on
every boot — and a sixteen-page staging object), and two stack sizes (shell and fsd,
four pages to sixteen: a parsed manifest is an eight-kilobyte value and a mounted
`Volume` carries its cache by value, and both floors were found by real faults with the
addresses in the changelog). **Writability rides the badge's top bit** — `tcp::handle`'s
listener-bit precedent, kernel-minted, never from arguments — and inherits *downward*
through `OPEN_AT` only: write authority over a directory already implies authority over
its children. The shell holds `/pkg` and nothing above it; the deliberate
not-the-root narrowness of RFC 0016 survives packaging intact. One latent seam flagged
rather than fixed: `DRAIN`'s kernel copy loop does not advance its destination across a
multi-frame object — harmless for every current single-page user, written down in
TRACKER before it can surprise anyone.

The installed set lives at `/pkg` on RFC 0016's filesystem: one directory per package
holding its payload, plus the manifest recorded beside it as the installation record —
no second database to disagree with the first. The shell grows one command family
(`pkg install <file>`, `pkg list`, `pkg remove <name>`), because the shell is already the
actor that holds filesystem and spawn authority; a separate `pkgd` domain is an isolation
boundary with no adversary behind it (alternatives, below). Failure order is chosen so a
crash cannot lie: **install writes payload first, record last** — a torn install leaves
sweepable droppings and no claim of success; **remove deletes the record first, payload
after** — a torn remove leaves droppings and no claim of presence. Hashes are verified on
install, before the record exists.

**Step 4's verdict, over the paragraph below that specified it.** `pkg run hello` at a
live prompt: the record read back off the disk and parsed with the grammar that admitted
it, the binary read out of the installed tree through `READ_INTO` (`WRITE_FROM`'s mirror,
added for exactly this — `MAP` lends one page and a binary is bigger), the intersection
rule enforced *before any domain exists*, and the program spoke through the console its
manifest asked for. The over-ask is gated live: `greedy`, the same binary under a manifest
asking for a DMA window, is refused whole with nothing granted. Two findings worth their
ink: the first `WRITE_FROM`/`READ_INTO` used the block store's own transfer page as a data
buffer, and every cache miss during the very operation being served ran device traffic
through it — installed records came back the right length and the wrong bytes; both arms
now use stack buffers and the changelog names the disease. And granting the child's
console under a fresh badge was refused with `INSUFFICIENT_RIGHTS` — the shell's console
is itself badged, and rights monotonicity does not allow identity swaps even for the
spawner; the child inherits the badge the shell's own capability carries. One stated gap:
the manifest declares `entry hertz` and the spawner passes zero — it cannot know the rate
— so the first installed program that keeps time is the trigger for threading it through.

**Step 5's verdict**: removal was implemented beside install at step 3 (the record
deleted first, the payload after) and is now gated with the strongest ordering proof
visible from outside — after `pkg remove hello`, running refuses off the gone record,
and a **reinstall succeeds**, which no surviving dropping would allow: a leftover file
or directory would trip the same `EXISTS` refusal the second-install gate proves works.
The full cycle — install, list, refuse-duplicate, run, refuse-over-ask, remove,
refuse-run, reinstall — is one typed conversation in the shell test.

Running an installed program is RFC 0017's machinery with the manifest as the grant list:
the starter grants **the intersection of what the manifest requests and what the starter
holds**, and a manifest asking beyond the starter's own authority is refused whole — no
partial grants, no silent narrowing, the exact rule the driver enumerator and RFC 0022
already enforce. Removal makes the program refuse to spawn again, and the boot test
watches that refusal happen.

### Concurrency, failure, `unsafe`

One actor (the shell) drives package operations; `fsd` owns file consistency under its
journal; there is no shared mutable state and no new lock. Hostile input is the parsers'
whole job and they are fuzzed. Out of space mid-install is a refusal with both numbers,
and the droppings sweep covers it. `unsafe` in `pkg/`: **zero**, budget written as zero.
Kernel `unsafe` added: **zero** — if a step needs kernel code, the design claim failed and
this RFC says so.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **TOML/JSON manifests** | A `no_std` parser for a general config language is hundreds of lines of hostile-input surface for zero expressive gain over a line grammar; every field this manifest needs is `key value` | A manifest field that genuinely needs nesting deeper than a section |
| **A new archive format** | The ustar subset is already documented, parsed, and boot-proven on this machine; a second container format is a second parser to fuzz and a second spec to keep honest | ustar's 100-char name limit or 8 GiB member limit actually bites |
| **A `pkgd` daemon domain** | The shell already holds exactly the authority installing needs; a daemon adds a domain boundary with no adversary on the other side of it — installs come from a file the operator named | Installs start arriving from the network, where the far side *is* an adversary |
| **Content-addressed store (the Nix shape)** | Buys atomic upgrades and deduplication for a system with fourteen programs and no upgrade story yet; the cost is a naming indirection every tool must learn | Phase 3's A/B update work, where atomicity stops being theoretical |
| **Signatures now** | A signature without key storage, distribution, or revocation is theatre that trains reviewers to see green checkmarks; the honest present tense is "corruption-detected, unsigned" | Phase 3's secure-update chain, which owns keys — the manifest's hash lines are built to be its payload |
| **Install-time scripts** | A package that runs code at install time is ambient authority by definition — the one thing this system exists to refuse. Not deferred: **refused**. The manifest declares; the installer acts | Nothing. A need that looks like a postinst is a need for a declared capability |

## What is refused, and when that changes

| Refused | Why | Trigger to build |
|---|---|---|
| Network fetch / repositories | No transport security and no resolver; an unsigned package over plaintext HTTP is an arbitrary-code vending machine | Signatures (Phase 3) and a name-to-address story, together — neither alone |
| Signatures and trust roots | See alternatives — theatre without key infrastructure | Phase 3 secure update |
| Dependency resolution | Every current package depends on the kernel ABI and nothing else; a solver with no instances is untestable code | The first package that genuinely needs another at run time |
| Upgrade / rollback | Versioning without A/B slots and rollback protection is a way to brick the writable filesystem politely | Phase 3's immutable-root and A/B work |
| Side-by-side versions | One version stream per name keeps `/pkg/<name>` honest; two versions is dependency resolution wearing a hat | Same trigger as the solver |

## Testing plan

Host: the manifest grammar (every field, every malformed line, the grant vocabulary),
the archive walk (truncation, name escapes — `..`, absolute paths — oversize members),
SHA-256 against the FIPS vectors, and fuzz targets for manifest and archive both.
Determinism: `mkimage` run twice, byte-identical, gated; the migrated image's member list
compared against the outgoing rule's once, at the migration commit. Boot gates per
placement: the install/run/remove cycle on the writable filesystem — installed and
verified, spawned with manifest-derived grants and *reporting through them*, removed and
**refused** on re-spawn; a bad-hash package refused before any record exists; an over-asking
manifest refused whole. Torn-install recovery exercised by the failure-order tests
host-side, where the journal's promises are already proven.

## Unresolved questions

1. **Does the kernel's own bring-up read these manifests?** Today the kernel wires each
   boot service's grants in code. Migrating that to manifest-driven grants would make
   `packages/` the single authority database — and would put a parser on the boot path
   and a policy file inside the trust boundary. Deliberately not decided here; the image
   half of this RFC neither needs it nor forecloses it.
2. **What does "self-hosts its own userspace utilities" require beyond this?** The exit
   criterion needs a definition — probably "a utility can be built, packaged, installed
   and run without editing the Makefile or the kernel" — and this RFC's steps are the
   instrument that will show whether that definition is met or merely approached.
   **Measured at step 6 against what `bin/hello` actually required**: its own crate, its
   `manifest.in`, and three Makefile stanzas (build, `.bpk` emission, one `--file` line)
   — and **zero per-utility kernel edits**, which is the half that matters. The kernel
   half of the definition is met; the Makefile half is approached, not met: the stanzas
   are boilerplate a pattern rule could fold away, and naming what ships in the image
   should arguably stay an explicit decision. The remaining distance is one build-system
   refactor, not a design question — recorded here, not resolved here.
3. **Does `fs.img` assembly also migrate to `mkimage`?** ~~Decided when step 2 touches
   it.~~ **Answered at step 2: no.** `mkfs` owns the on-disk format and keeps building
   `fs.img`; `mkimage` carries it into the image as a declared build artifact
   (`--file fs.img=…`), exactly like a static file except that it is built. Two tools,
   one image, each owning its own format — folding the filesystem writer into the
   package assembler would have made one tool own two formats to save one Makefile line.

## Implementation plan

1. **The crate and the format**: `pkg/` — manifest grammar and parser, the archive walk
   (reusing the kernel's ustar subset by leaf-crate extraction if it separates cleanly,
   RFC 0028's ELF pattern; a documented-subset twin tested against the same corpus if
   not), SHA-256 with vectors, fuzz targets. Host-only; `unsafe_budget = 0`.
2. **The image becomes packages**: `packages/` manifests for all fourteen programs,
   `mkimage`, the determinism gate, the member-list comparison, and the Makefile `cp`
   list retires. Question 3 is answered in passing here.
3. **The installed set**: `/pkg` layout, install through the shell onto RFC 0016's
   filesystem from a `.bpk` staged in the image, hash verification before the record,
   payload-first/record-last order — first boot gates.
4. **Run what was installed**: spawn with manifest-derived grants, intersection rule,
   over-ask refused whole — gated, including the refusal.
5. **Remove**: record-first order, droppings swept, re-spawn refused — gated, including
   the refusal.
6. **Measurement and the ledger**: install and remove priced through the journal
   (bytes, calls, wall clock), the gate count moves with its composition stated, and the
   bullet closes with question 2's definition tested against what exists. **Done, with
   the numbers in the report itself**: every `pkg install` says its price — for `hello`,
   15,408 payload bytes through the journal in 5 writes, 320–382 million cycles across
   three installs of one boot; a removal, 221 million — raw cycles on purpose, because
   the shell was not told the rate and the boot log carries it for whoever converts.
   The prices are gated as present, not as magnitudes: a slow disk is not a broken
   package manager, but an install that will not say what it cost is a broken
   instrument. The boot-gate ledger is unchanged at 51 per placement — steps 3 to 5
   live in the shell test's typed conversation, which grew by thirteen asserted
   replies (install, list, duplicate refused, over-ask refused, run, spoken greeting,
   reaped ending, removal, refused rerun, clean reinstall, both prices).

Steps 1–2 touch no guest code; step 3 is the first boot-visible change; steps 4–5 ride
RFC 0017's machinery unchanged or the design claim fails; step 6 is the same discipline
every accepted RFC ends with.
