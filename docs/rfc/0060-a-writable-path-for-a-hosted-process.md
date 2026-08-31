# RFC 0060: a writable path for a hosted process

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-31 — scope only, nothing built.** Written to be argued with before any code exists |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | libc / userspace |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md), [RFC 0030](0030-packages.md) (the writable-badge mechanism), [RFC 0059](0059-an-execve-that-runs-a-program.md) (the staging object) |

---

## Summary

A hosted Linux process can create a file, write to it, and read it back. Today
every write is refused: `open_the_file` answers `EROFS` before looking at
anything, because the directory capability `bin/linuxd` holds carries no
authority to change what is under it.

This is the last of `docs/roadmap.md`'s L1 list that is a *mechanism* rather
than breadth — a shell that cannot redirect output is not a shell.

## Motivation

`docs/roadmap.md`'s L1 row names what remains: *"terminal `ioctl`s, `getdents`,
`stat`, a writable path, and the signal gaps a shell notices"*. The `ioctl`s,
`getdents` and `stat` are done; `execve` was closed by RFC 0059. **A writable
path is what is left of the list that a program cannot work around.**

Concretely, with RFC 0059 a hosted `sh` can now start a program. It still
cannot run `echo hi > file`, `cc -o prog prog.c`, or anything that keeps state.

## What already exists, and what genuinely does not

**This is a smaller change than it looks**, and the scoping matters more than
the design:

| Piece | State |
|---|---|
| The flag arithmetic | **Done.** `file::plan_openat` already computes `readable`, `writable`, `create`, `exclusive`, `truncate`, `append`, `directory`, host-tested. `open_the_file` computes the plan and then throws it away with `let _ = plan;` |
| The protocol | **Done.** `dir::CREATE_AT`, `WRITE_FROM`, `REMOVE_AT` and `MAKE_DIRECTORY_AT` have existed since RFC 0030 and are driven by `bin/shell` today |
| The authority mechanism | **Done.** Writability is a **badge bit** (`dir::WRITABLE`, bit 63), minted only by the kernel and checked by `bin/fsd`. `bin/shell` holds exactly one such handle, for `/pkg` |
| A memory object to stage bytes through | **Done.** RFC 0059 gave the adapter a 16-page staging object; `WRITE_FROM` takes a caller slot and a length |
| The adapter holding a writable handle | **Missing.** This is the whole of the new authority |
| `write` on a `Kind::File` descriptor | **Missing.** The dispatch has the arm and refuses in it |
| `unlink`, `ftruncate`, `mkdir` | **Missing** |

## Design

### Where a hosted process may write, and where it may not

**Not its root.** The adapter's `ROOT_DIR` is `sub` on the disk, granted
`READ | DERIVE` with a read-only badge, and it stays exactly that. A second
capability is granted for a **writable subdirectory**, and a hosted process
sees it as one name inside its root.

That follows `bin/shell`'s `/pkg` precedent rather than inventing a shape: one
narrow writable handle beside a read-only root, so *what can be changed is a
property of which capability is held*, not of a flag on a call. A hosted
process that never opens that directory cannot write anywhere at all, and no
check enforces that — it is structural.

**Named `/tmp`, and the name is a decision rather than a default.** A program
looking for scratch space looks for `/tmp` before anything else, and a name a
Linux user would guess is worth more than an invented one.

But the familiar name must not imply a guarantee this does not offer, and here
it would: `/tmp` on Linux is world-writable, per-boot and shared by convention
with rules about who may unlink what. This is one directory behind one
capability, shared by every hosted process for no principled reason (see
unresolved question 1), and not cleaned on boot. **If that gap misleads
anyone, the name is what should change, not the guarantee** — a familiar name
that lies is worse than an unfamiliar one that does not. Recorded here so the
choice is deliberate and revisitable rather than discovered later by somebody
who trusted it.

### The sequence

```
   openat(O_WRONLY|O_CREAT)   plan_openat says create + writable
                              -> CREATE_AT on the writable directory
   write(fd, buf, n)          COPY_IN from the hosted process
                              -> WRITE_FROM, one page per call, at the offset
   close(fd)                  the capability goes back, as it does today
   openat(O_RDONLY)           the existing read path, unchanged
```

### What each new call costs

* **`CREATE_AT`** replaces `OPEN_AT` when `O_CREAT` is set and the name is
  absent; `O_EXCL` decides whether an existing name is an error or is opened.
* **`write`** is `COPY_IN` from the hosted process into the staging object,
  then `WRITE_FROM` with the descriptor's offset. One page per call, so the
  loop is the adapter's — the same shape `READ_INTO` already has.
* **`unlink`** is `REMOVE_AT`. **`mkdir`** is `MAKE_DIRECTORY_AT`.
* **`ftruncate`** has no protocol call and is out of scope; `O_TRUNC` on create
  is free because a created file is empty.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Make the existing `ROOT_DIR` writable** | One capability instead of two, and every path a hosted process can name becomes writable — including the files the read gates assert on. The containment claim in RFC 0031 I3 is that a hosted process reaches only what it was granted; making the one thing it was granted writable throws away the distinction between reading and changing for no gain | The root and the writable area ever need to be the same directory, which would itself want an RFC |
| **A `tmpfs` in the adapter — writes to memory, not the disk** | No filesystem service needed, so it would work on every lane instead of two. It is also a second filesystem implementation inside the most authority-concentrated program in the system, which RFC 0031 exists to prevent, and it would not survive the process | Never for L1. A memory filesystem is a *service*, if it is anything |
| **Per-process writable directories** | Closer to real isolation: each hosted process gets its own. It needs a directory created per process and destroyed with it, which is process lifetime work RFC 0033 does not have | L2, where process groups and users arrive |
| **`ftruncate` and `O_TRUNC` on an existing file** | No protocol call exists; adding one is a change to a service two programs share | A program actually needs it — likely as soon as a real shell redirects onto an existing file |

## Impact on existing design documents

* **`docs/roadmap.md`** L1 row: *"a writable path"* moves from the remaining
  list to done, and the row must keep saying what is still missing.
* **`docs/security.md`** T11: the adapter gains **one writable directory
  capability**. That note enumerates what a compromise of `bin/linuxd` reaches,
  and this is the first authority it has ever held to *change* anything outside
  itself. It must say so plainly.
* **`docs/rfc/0031`** I3's containment claim is unchanged in kind and must be
  restated in terms of two capabilities rather than one.

## Security implications

**This is the first time the adapter can change state outside its own memory**,
and that deserves the plainest possible statement rather than a reassurance.

* The writable handle names **one directory**, and there is no way up out of it
  — the same structural property the read-only root has, and for the same
  reason: the capability names a directory and carries no path.
* A compromised `bin/linuxd` could create, fill and remove files under that
  directory. It could not touch the root above it, the packages, the image, or
  any other domain's memory.
* **The badge is the authority, and only the kernel mints it.** `bin/fsd`
  refuses a write whose badge lacks `dir::WRITABLE`, and a badge cannot be
  forged by a holder — which is what makes "the adapter holds one writable
  directory" a checkable claim rather than a convention.
* **New untrusted input**: none of a new kind. The bytes come from a hosted
  process through `COPY_IN`, which is the path `write` to the console already
  uses, and the path is bounded by the staging object.

## Performance implications

A hosted `write` costs one `COPY_IN` and one `WRITE_FROM` per page, against a
console write's single message. The journal decides when a dirty page goes
home, so a write's *durability* cost is RFC 0016's and not this RFC's. What
should be measured, on the boot that first does it: bytes per second through
`WRITE_FROM` against `READ_INTO`'s existing figure, so the two directions are
comparable rather than one being asserted to be like the other.

## Testing plan

* **Host** — `plan_openat`'s write flags are already covered; what is new is
  the *refusal* arithmetic: creating without `O_CREAT`, `O_EXCL` on a name that
  exists, and a write to a descriptor opened read-only. All decidable without a
  machine.
* **QEMU** — a hosted program creates a file under the writable directory,
  writes a line, closes, reopens it read-only and prints what it reads. The
  gate asserts the line, which nothing else on the machine can produce. It runs
  on the lanes with a filesystem service and skips honestly elsewhere, exactly
  as RFC 0059's gate does.
* **Armed both ways**, before being believed: a write that is silently dropped
  must fail the gate, and a write to the **read-only root** must still answer
  `EROFS` — the second is the containment claim and is the more important arm.
* **Real hardware**: not reachable. The SR550 has no disk this project's driver
  accepts, so it has no filesystem service; this skips there for the same
  recorded reason every filesystem gate does.

## Unresolved questions

1. **Is the writable directory shared between hosted processes?** As scoped,
   yes — one directory, one capability, every hosted process sees it. That is
   wrong for isolation and right for L1's cost, and it is the first thing L2
   should revisit. It is called out because a shared scratch directory between
   mutually distrusting processes is a real weakness, not a simplification.
2. **What creates it?** `bin/fsd` creates `pkg` at startup and reports its
   handle; this would follow that. The alternative is the kernel creating it
   when it formats the disk, beside `sub` and `inner`.
3. **The file-size ceiling is 40 KiB** — `Volume::write` reaches ten direct
   blocks and no indirect one. Every hosted write inherits that, and a program
   that exceeds it gets a short write. Whether a short write or an error is the
   honest answer is a decision this RFC should make before it is built.
4. **The adapter's CSpace is full.** RFC 0059 took slot 25 and moved
   `HANDLE_FLOOR` to 26; this takes another and moves it to 27, leaving 61
   hosted-domain handles against `MAX_DOMAINS` of 64. The trade is small and
   real, and the third such change should probably reorganise the map instead
   of shaving the same pool again.

## Implementation plan

1. `bin/fsd` creates the writable directory and reports its handle, as it does
   for `pkg`; the kernel mints the writable badge into a new adapter slot.
2. `open_the_file` stops discarding `plan_openat`'s answer: writable opens go
   to the writable directory, `O_CREAT` to `CREATE_AT`, and the read-only root
   still answers `EROFS`.
3. `write` on a `Kind::File` descriptor: `COPY_IN`, then `WRITE_FROM` at the
   descriptor's offset, looping a page at a time.
4. `unlink` and `mkdir`.
5. The gate, armed both ways — the write, and the refusal on the read-only
   root.
6. `docs/security.md` T11, `docs/roadmap.md`'s L1 row, and `TRACKER.md`.
