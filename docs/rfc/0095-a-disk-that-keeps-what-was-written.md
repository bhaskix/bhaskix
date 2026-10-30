# RFC 0095: A disk that keeps what was written

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-30 — built and gated the same day.** The lead chose the behaviour before it was written: format only a disk that carries the project's marker, keep one that holds this system's filesystem, leave anything else untouched, and have `make demo` keep its disk. `make test-disk-keeps` boots three times and passes, and each of its two arms turns it red. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel / fs / userspace (`bin/fsd`) / tools |
| **Milestone** | the first release (`v0.1.0-preview`): one of its stated limits, removed |
| **Depends on** | [RFC 0015](0015-filesystem.md) (the journalled filesystem), [RFC 0016](0016-capability-in-a-reply.md) step 3 (the journal-on-disk self-test that formatted), [RFC 0030](0030-packages.md) (`/pkg`), [RFC 0060](0060-a-writable-path-for-a-hosted-process.md) (`sub/tmp`) |

---

## Summary

A boot decides what it may do with the domain disk from that disk's first block:

| Sector 0 holds | The boot |
|---|---|
| the marker `BHASKIX-DOMAIN-DISK-SECTOR-0` | formats it and runs the journal's whole self-test, as every boot did until now |
| this system's filesystem, its superblock intact | **mounts it and keeps it** |
| anything else, or this system's magic over a superblock it cannot accept | **writes nothing to it** and mounts nothing from it |

A package installed on one boot is there on the next, and a disk that is not the project's is
never written.

## Motivation

**Nothing written survived a reboot, and no RFC chose that.** The journal self-test of RFC 0016
step 3 (`journal_on_disk`) laid a fresh filesystem on the disk at every boot, to prove the journal
against a real device. The product inherited it.
- The release notes and two guides had to say "remake both files before every boot".
- A second boot on the same file failed its own block self-test. The format had written the
  superblock over the marker that test reads (TRACKER §3, filed 2026-10-19).

**And it formatted whatever was there.** The self-test ran whether or not the block service had
found the marker (`kernel/src/lib.rs`, the boot's disk sequence). A virtual machine started with a
real data disk in the second virtio place would have lost it. It is the same class of hazard as
`bin/ahcid` writing the last sector of any SATA disk, fixed the same day by the lead's choice:
write only to the test disk.

## Design

**One classification, host-tested.** `classify_domain_disk(head, blocks)` in the kernel answers
one of four kinds:
- **`Marked`:** the head starts with `bhaskix_abi::block::DOMAIN_DISK_MARKER`.
- **`Ours`:** `bhaskix_fs::Superblock::read_head` accepts it, which checks magic, version, block
  size and checksum, and a layout that fits the device.
- **`OursUnreadable`:** the magic is right but the superblock is refused, as with another version
  or damage.
- **`Foreign`:** anything else, a blank disk included.

The rule is a pure function because getting it wrong formats somebody's disk. Four host tests
cover it, and with every disk classified as formattable three of them fail.

**`journal_on_disk` reads block 0 first, with the store it writes through, before anything is
written:**
- **`Marked`:** the path that existed, unchanged: the refused-write probes, the format, the tree,
  the staged programs, and the deliberate interruption one write after a commit and its replay.
  The refused-write probes now run **only here**. One of them names sector 0 through a write-only
  capability, so if the refusal it tests ever regressed, the write would land.
- **`Ours`:** `keep_the_disk`.
  - **The mount:** `Volume::mount` replays a commit an earlier boot was interrupted after.
  - **Repairs:** the files the shell's gates read (`on-a-disk`, `greeting`, `sub/inner`) and
    `sub` are made only where missing. A file called `sub` is somebody's, and the boot stops
    rather than create over it.
  - **The boot's own programs** (`sub/hosted`, and `sub/busybox` when asked) are **replaced**,
    because the copies there are an earlier image's.
  - **A journal check that destroys nothing:** a file is written, read back off the disk and
    removed. The deliberate interruption runs only on a disk nobody's data is on.
  - **`/pkg` is untouched.**
- **`OursUnreadable` / `Foreign`:** nothing is written. The journal's line says which, and `bin/fsd`
  is not started: it writes `pkg` and `sub/tmp` where they are missing, and a disk left alone is
  one it must not.

**The block self-test reads one sector,** which cannot hold a whole superblock. So it tells the
three apart by the marker, the filesystem's magic, or neither, and prints a different line for
each. Every lane gate demands the exact line for the disk its harness attached. So a read path
that returned the wrong bytes prints a line no gate accepts, and calling a broken read "foreign"
cannot pass.

**`/tmp` starts empty.** On a kept disk, `sub/tmp` holds every earlier boot's scratch files. The
hosted probes `mkdir /tmp/made` on every boot, so boot 2 would meet boot 1's. `bin/fsd` now
empties it when it mounts it, as a Linux system's `/tmp` starts empty, through a new
`Volume::empty(directory, depth)`:
- one transaction per entry, through `Volume::remove`;
- subdirectories emptied first, bounded in depth;
- host-tested, its depth refusal armed.

If it cannot be emptied, no writable directory is handed out, and a hosted `open` says `EROFS`
rather than meet yesterday's files.

**`make demo` keeps its disk** (the lead's choice). `make demo-fresh` deletes it first, and the
banner says which disk it booted with.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Keep formatting every boot; accept the self-test's red line | It is a product that forgets what it was told, and a boot that formats whatever disk is second. | Never. |
| Format a blank (all-zero) disk too | A blank disk is not necessarily an unused one: a new volume a hypervisor attached for something else is blank. The marker is a deliberate act and costs one `printf`. | Users make disks with a tool of the project's own that writes the marker. |
| Run the whole crash-and-replay self-test on a kept disk too | It interrupts a transaction on purpose. The journal is built to survive that, but testing it to destruction on someone's data is a choice the format path does not need to make, and that path still runs on every lane. | Never on a kept disk. |
| Clear `/tmp` in the kernel's kept path | `/tmp`'s lifetime is the filesystem service's policy, and `bin/fsd` already creates it at mount. | — |
| Make the hosted probes idempotent instead of emptying `/tmp` | It fixes the probes and not the next program that assumes a clean `/tmp`. | — |

## Impact on existing design documents

- **The guides:**
  - [`get-started.md`](../guide/get-started.md): "Remake both files before every boot";
  - [`shell-and-packages.md`](../guide/shell-and-packages.md): "Nothing installed survives a
    reboot".

  Both are rewritten, with their transcripts re-run.
- **[`release-notes.md`](../release-notes.md):** the limit and its known-issues row move to
  fixed. The release is not published, so the notes describe what it will do.
- **The Makefile's** comment on the domain disk; `tools/demo.sh`; the README's demo paragraph.

## Security implications

- **This removes a way a boot could destroy data it had no business touching.** A boot writes
  only to a disk the project marked, or to one this system formatted.
- **No new authority.**
- **The superblock is read from a device before it is trusted, a parser of untrusted input.**
  `Superblock::read_head` already checks the checksum and every field used as an index. It is
  exercised by the fs crate's host tests, and fuzzed by `fuzz/fuzz_targets/fs_image.rs`.

## Performance implications

**A kept disk's boot writes less than a fresh one's:**
- no format;
- a three-file check;
- the programs re-staged, which was the cost of every boot already.

**`/tmp`'s emptying is one transaction per entry**, five on a boot after the hosted probes.

## Testing plan

- **Host:**
  - the classification, four tests, armed;
  - `Volume::empty`, three tests, its depth refusal armed.
- **QEMU, `make test-disk-keeps`** (in `make test` and CI), on the demo's device profile:
  1. **Boot 1:** a marked disk is formatted, the journal's full self-test runs, and `hello.bpk` is
     installed.
  2. **Boot 2, on the same file:**
     - the block service and the journal report the kept filesystem;
     - `bin/fsd` mounts it;
     - `1 installed`, and `hello` runs;
     - **no red line that boot 1 did not also have**. It compares with boot 1 rather than demand
       none, because the machine's networked self-tests have intermittent defects of their own.
  3. **Boot 3:** a disk with somebody else's header and random bytes keeps its sha256.
- **The arms:**
  - **`bin/fsd` not emptying `/tmp`:** boot 2 gets a red line boot 1 did not have.
  - **Every disk formatted, as before:** boot 2 loses the package, and boot 3's disk changes.
- **Every other lane** starts from a fresh marked disk, and their gates are unchanged.

## Unresolved questions

None for the lead; the behaviour was chosen before this was written.

**Left out:**
- **A user command to wipe the disk.** Remaking the file does it, as `make demo-fresh` shows.
- **Disks that are not virtio.** The SATA disk was settled by the `ahcid` fix, and the SR550 has
  no domain disk.

## Implementation plan

1. **Classification and the kept path, built 2026-10-30:**
   - `classify_domain_disk` and its tests;
   - `DOMAIN_DISK_MARKER` in `abi::block`;
   - `keep_the_disk`, and `stage_programs` lifted out of the format path so both paths stage
     alike;
   - the three-way block self-test;
   - `start_fs_domain` skipping a disk left alone.
2. **`/tmp` emptied, built 2026-10-30:** `Volume::empty` and its tests; `bin/fsd` calls it.
3. **The lane and the demo, built 2026-10-30:** `tests/qemu/disk-keeps-test.sh`,
   `make test-disk-keeps`, `make demo-fresh`, and the demo's banner.
4. **Documents:** the guides, the release notes, the README and TRACKER.
