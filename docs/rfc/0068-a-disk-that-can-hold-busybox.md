# RFC 0068: a disk that can hold BusyBox

| | |
|---|---|
| **Status** | 📋 **Specified 2026-09-04, not implemented.** The measurements are done and the decision is the cost, not the mechanism |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | fs (`build/domain-disk.img`, `bin/fsd`) / kernel staging |
| **Milestone** | Phase 2 — Linux personality, application milestone **L1** |
| **Depends on** | [RFC 0059](0059-an-execve-that-runs-a-program.md), [RFC 0064](0064-a-read-that-lands-where-the-caller-says.md), [RFC 0065](0065-the-block-the-format-already-had.md), [RFC 0067](0067-more-than-one-block-per-round-trip.md) |

---

## Summary

`docs/roadmap.md`'s **L1** row names BusyBox as its first application. Everything needed to run one
is built. One number stops it: the disk this project builds is **1,048,576 bytes** and BusyBox is
**2,172,376**. This RFC is about what to do with that number, because the obvious answer — make the
disk bigger — costs between **3.6 and 57 seconds on every boot**, and that price should be chosen
deliberately rather than discovered in CI.

## Motivation

`TRACKER.md` §4 said until 2026-09-04 that a hosted `sh` cannot run a command because *"BusyBox is
2,172,376 bytes against a 65,536-byte staging object"*. That was three days stale. RFC 0064 gave
`READ_INTO` a landing offset so the loader streams a program in pieces, and `answer_execve` says so
in its own comment: *"`E2BIG` for a program larger than the staging object is gone — RFC 0064."*

So the pieces are in place, and it is worth being precise about how many:

* **The program is present.** BusyBox is staged into the initrd by two `--file bin/busybox=` lines
  in the `$(INITRD)` rule, which is assembled twice and byte-compared.
* **The loader does not care how big it is** — RFC 0064.
* **The filesystem can hold it.** RFC 0065 took a file past ten blocks by using the indirect block
  the format always had.
* **`execve` runs a real ELF off the filesystem** with argv and environment — RFC 0059.

What is left is the disk, and the time it takes to write to it.

## Design

**Grow `$(DOMAIN_DISK)` to 4 MiB and stage BusyBox into it at format time**, beside the files the
kernel already writes there.

Four megabytes rather than three: 2,172,376 bytes of program, the filesystem's own metadata, and
the room a package install needs — the disk went from 256 KiB to 1 MiB on 2026-09-01 precisely
because `bin/hosted` and a package install did not both fit, and the install failed with `no space`
rather than anything about itself. Leaving the same margin twice is cheaper than finding it twice.

**The write is the cost, and it is measured.** `hosted stage` reports 6,300 to 107,000 microseconds
a block across five boots of one unchanged image — a seventeenfold spread filed as its own defect in
`TRACKER.md` §3 the same day this was written. BusyBox is 531 blocks. So:

| | per block | 531 blocks |
|---|---|---|
| best observed | 6,318 µs | ≈ 3.4 s |
| median-ish | 15,698 µs | ≈ 8.3 s |
| worst observed | 107,015 µs | ≈ 57 s |

Against a `disk format` that writes 128 blocks in 74–93 ms after RFC 0067. The two paths differ in
that staging goes through the filesystem — cache, journal, indirect blocks — and the format writes
blocks directly.

**This RFC does not propose paying that on every lane.** It proposes one of the three below, and
says plainly that the choice is a scope decision rather than an engineering one.

### Option A — stage BusyBox on the lanes that have a filesystem, always

Simplest. Costs the table above on `iommu`, `placements` and the shell lanes, every boot, including
CI. At the worst observed rate that is most of a minute per lane, which would change what `make test`
costs from roughly twenty minutes to something nobody will run before pushing.

### Option B — stage it behind a flag, off by default

`BHASKIX_BUSYBOX=1` stages it; nothing else changes. L1 becomes demonstrable on demand and provable
in one dedicated CI job, and the ordinary lanes keep their present cost. The gate for the hosted
shell runs only where the flag is set, and says `skipped: this image has no BusyBox` elsewhere —
the phrasing this project already uses for lane-conditional gates.

### Option C — fix the staging rate first, then choose

The 17× spread is an open defect. Optimising a path whose cost is not a constant is optimising the
wrong half; and if staging settles near its *best* observed rate the whole question shrinks to three
and a half seconds, which Option A could carry.

**Recommended: C, then B.** The variance is a defect with an open row; closing it costs nothing that
is not already owed, and it changes the price of every option here. B is what to do if C does not
land, because it makes L1 provable without making the suite unrunnable.

## Alternatives considered

**Grow the disk and write BusyBox lazily, on first `execve`.** Rejected for this RFC: it moves the
seconds from boot to first use, where they are more visible, and it needs a writable path from the
adapter that the boot-time staging already has.

**Ship a smaller BusyBox.** A custom build with fewer applets would fit today. Rejected as a
measurement trick: L1 names BusyBox, and a version chosen to fit the disk proves the disk, not the
personality.

**Put BusyBox in the initrd only and exec it from there.** It is already in the initrd, and this is
the tempting shortcut. Rejected because `execve` resolves through the adapter's **directory
capability**, which is a badged capability to a directory on the mounted disk — reaching into the
initrd instead would be a second path into the loader with different authority, which RFC 0031's
"an adapter above Bhaskix services, never a reimplementation inside them" exists to prevent.

## Impact on existing design documents

* `docs/roadmap.md` **L1** — its "what is left" list should name the disk, not the staging object.
* `TRACKER.md` §4's libc row — corrected 2026-09-04; this RFC is what it points at.
* `docs/rfc/0059` — its "the image must fit the staging object" limit was already superseded by
  RFC 0064; nothing further here.

## Security implications

None new. The program crosses no boundary it did not already cross: it is written to the same disk
by the same kernel-side format path, and read by the same adapter through the same directory
capability. A larger disk does not widen what a compromised `bin/linuxd` holds — `docs/security.md`
§1's T11 note already prices the directory, and its reach is the directory, not the disk's size.

The one thing worth stating: BusyBox is a **2 MB program from outside this project** running in ring
3 under the Linux personality. That is the point of L1, and the isolation argument is unchanged —
it holds a directory capability, descriptors the adapter owns, and nothing else. It is not a new
trust decision, but it is the first time the decision carries something this large.

## Performance implications

The table above, and nothing else: no lane that does not stage BusyBox changes at all.

## Testing plan

1. The existing hosted gates continue to pass unchanged on every lane.
2. A new gate, on whichever lanes stage it: a hosted `sh` runs one command and its output appears.
   **Armed both ways before being believed** — a command that produces no output, and a shell that
   is present but never reached, each watched red.
3. `disk format` and `hosted stage` timings recorded in the same boot, so the cost this RFC prices
   is visible on the lane that pays it rather than in this document alone.

## Unresolved questions

* Whether the staging variance (§3) is fixable, which decides between A and B.
* Whether a 4 MiB disk changes the format cost measurably — 128 blocks are formatted today, and a
  bigger disk formats more of them unless the format stays bounded.

## Implementation plan

1. Grow `$(DOMAIN_DISK)` to 4 MiB and confirm the format still bounds itself, measuring both timings.
2. Stage `bin/busybox` into `sub/` at format time, behind the flag chosen above.
3. The gate, armed both ways.
4. Update the roadmap's L1 row and §4's libc row to say what is left after this.
