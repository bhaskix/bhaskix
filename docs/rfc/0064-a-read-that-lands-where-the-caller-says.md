# RFC 0064: a read that lands where the caller says

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-01** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | filesystem (`bin/fsd`, `dir::READ_INTO`) / libc / userspace (`bin/linuxd`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0030](0030-packages-a-user-can-install.md), [RFC 0059](0059-an-execve-that-runs-a-program.md) |

---

## Summary

`dir::READ_INTO` lands bytes in the caller's object at **the file offset it read them from**. So a
caller that wants byte two million needs an object two million bytes long, and `execve` cannot run a
program larger than its staging object. One more argument — where in the object the bytes go — makes
the object a window that slides along the file instead of a copy of it.

## Motivation

RFC 0059 gave a hosted process an `execve` that runs a real ELF off the filesystem, and named its own
limit rather than implying the milestone was finished: the image must fit the staging object, which
is sixteen pages. **BusyBox is 2,172,376 bytes.** So the shell that RFC 0050–0058 taught to read a
line still cannot run the program a user would type a command into, and the reason is not the loader
or the ELF parser — both handle it — but one argument in a read.

The protocol's own words say why:

> `arg2` = the file offset — which is also the offset the bytes land at in the caller's object, so a
> linear read reassembles the file in place.

Reassembling the file in place is exactly right for the caller RFC 0030 wrote it for: `bin/shell`
reads a package image it intends to hold whole. It is exactly wrong for a loader, which does not want
the file — it wants each segment, once, at an address of its own choosing, and never needs two
chunks at the same time.

Growing the staging object instead is the alternative this rejects, and §Alternatives says why.

## Design

`dir::READ_INTO` takes a fourth argument:

| | |
|---|---|
| `arg0` | the caller's own slot holding a `Memory` object |
| `arg1` | how many bytes at most |
| `arg2` | the offset **in the file** to read from |
| `arg3` | the offset **in the object** to land them at |

The existing behaviour is `arg3 == arg2`, and every current caller is changed to pass exactly that,
so this commit changes no observable behaviour anywhere except where a caller asks for something new.
That is deliberate: a protocol change and a behaviour change in one commit cannot be bisected apart.

**Why a fourth argument and not a new method.** `READ_INTO`'s meaning does not change — it is still
"read bytes of this file into memory you name". What changes is that the destination stops being
implied by the source. A second method would leave two reads to keep in step, and the project has
already paid for that shape once: `docs/rfc/0029`'s v6 words went into a report array's spare zeros
because two writers of one layout disagreed about which words were free.

**The refusal.** A landing offset plus the count must fit the object, and a caller that asks for more
is refused rather than truncated: a truncating read is the kind of failure that produces a corrupt
program image and a puzzling crash much later. **Where that check lives was corrected during
implementation.** The draft said `bin/fsd` should make it and answer a refusal of its own; `bin/fsd`
does not know how large the caller's object is, and inventing an answer for it would have been a
second derivation of a bound the kernel already holds. The copy is performed by `method::FILL`, which
takes the destination offset and already refuses a range outside the object — so the service passes
the offset down and answers `dir::NOWHERE` when `FILL` declines, which is the path it already had
for exactly this.

**Scope, also corrected.** `fs::READ_INTO` and `dir::READ_INTO` are different protocols and only the
second is changed. The in-kernel VFS service's `fs::READ_INTO` is session-based and sequential — it
has no offset argument at all, so there is nothing there for a landing offset to mean. `bin/shell`
uses both, which is why the draft counted its callers wrongly.

## Alternatives considered

**Grow the staging object to hold the largest program.** Rejected. It sets a ceiling that has to be
raised again — 2.1 MB clears BusyBox and not the next thing — and every byte of it is memory a
compromised `bin/linuxd` holds, which `security.md` §1's T11 note has to price. A window that slides
is a fixed cost for any file size.

**Map the file instead of copying it.** `dir::MAP` lends the first page only, and a mapping the
adapter holds while it builds a child is a second thing to revoke on every failure path. The loader
already copies segment bytes into the child's space; this change only lets it copy them in pieces.

**Let the caller pass a whole scatter list.** More protocol than the problem needs. One offset makes
the object a window; a scatter list makes it an I/O engine, and nothing in the tree wants that yet.

## Impact on existing design documents

- `abi/src/lib.rs` — `dir::READ_INTO`'s contract gains `arg3`.
- `docs/rfc/0059` — its "the image must fit the staging object" limit is superseded; the note there
  points here rather than being deleted.
- `TRACKER.md` §4 and `docs/roadmap.md`'s L1 row — the BusyBox size limit is what they name.
- Every note in the tree that this "does not yet reach BusyBox" stops being true when step 4 lands,
  and not before — `TRACKER.md` and the roadmap row above are where those live.

## Security implications

The adapter's staging object does **not** grow, which is the point: `security.md` §1's T11 note
prices what a compromised `bin/linuxd` holds, and this keeps that figure at sixteen pages while
removing the size limit. The new argument is bounds-checked against the object the caller named, in
the service, before any copy — a landing offset is an offset into the *caller's own* memory, so a bad
one can only corrupt the caller, but "only" is not a reason to skip the check.

## Performance implications

A streamed load is more `CALL`s than a single read of a small file: one per page rather than one per
file. That is the same number of calls the current loop already makes — it already reads a page per
call — so the cost is unchanged for programs that fit today, and finite rather than impossible for
those that do not.

## Testing plan

1. ~~Host tests for the offset arithmetic and the refusal, in the crate that owns it.~~ **There is no
   such crate, and saying so is better than inventing one.** The arithmetic is `bin/fsd` passing one
   argument to `FILL`, and `bin/fsd` is a binary in its own workspace, outside `cargo test
   --workspace` — the same structural fact `Makefile`'s comment about `bhaskix-ahci` records. The
   bound is the kernel's `FILL`, which is where a host test for it belongs if one is wanted. What
   covers this change is step 4's gate and the existing callers' gates below.
2. A boot gate that `execve`s a program **larger than the staging object**, which is the case that
   cannot work today. Armed by shrinking the window and watching it fail.
3. Every existing `READ_INTO` caller unchanged in behaviour, proven by the gates that already cover
   them: the package install path, the shell's image read, and the kernel's own multi-page read.

## Unresolved questions

Whether the loader should stream segment by segment or page by page across the whole file. Page by
page is simpler and is what step 4 does; segment by segment would skip the gaps between segments,
which for a typical binary is a small saving and one more thing to get wrong.

## Implementation plan

1. **The protocol.** `arg3` in `abi`, honoured by `bin/fsd` and the in-kernel VFS service, with the
   bounds check and its refusal. Every caller passes `arg3 = arg2`, so nothing changes yet.
2. **Host tests** for the arithmetic and the refusal.
3. **The loader streams.** `answer_execve` reads the ELF header and program headers first, then for
   each `PT_LOAD` copies the file's bytes into the child a window at a time, so the staging object
   bounds the window rather than the file.
4. **A gate**, with a program deliberately larger than the window, armed red.
