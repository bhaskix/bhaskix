# RFC 0098: A program that can find itself

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-10-31 by the project lead**, on CI run 893's green. Drafted, built and gated the same day. No questions: the one rule that decides it is RFC 0005's. Drafted at the lead's request, ahead of its recorded trigger. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`, `personality`) |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — two rows of TRACKER §4's *Carried out of RFC 0005* |
| **Depends on** | [RFC 0005](0005-linux-abi-compatibility.md) (the rule against an invented path), [RFC 0033](0033-what-a-hosted-process-is.md) step 10 (`/proc/self/status` and `maps`), [RFC 0059](0059-an-execve-that-runs-a-program-off-the-filesystem.md) (an `execve` with argv and environment) |

---

## Summary

Three things a Linux program asks about itself:
- `readlink("/proc/self/exe")`, the path of its own program;
- `/proc/self/cmdline`, its arguments;
- `/proc/self/environ`, its environment.

They are answered for a process `bin/linuxd` started with `execve`, which is the only kind whose
path it knows. Any other process is told `ENOENT`, as RFC 0005 decided: a hosted process need not
have an image path at all, and inventing one would be the first thing this adapter made up.

## Motivation

TRACKER §4 carries both rows to L1:
- **`readlinkat` and `/proc/self/exe`**: "the first program that needs its own path";
- **`cmdline` and `environ`**: "the first program that reads them -- the reason given for leaving
  them out went with RFC 0059".

Neither trigger has fired. The lead asked for them now, ahead of it, as L1 breadth.

**Who asks:**
- BusyBox calls `readlink("/proc/self/exe")` at start (TRACKER's trace of its `echo`), is told
  `ENOSYS`, and carries on.
- ~~Go's runtime reads it too (RFC 0086's table)~~ -- **not the Go server here**: its
  `refused -ENOSYS` list, traced from before its first call, reads `157 234` before this RFC (CI
  run 892) and after, with no `readlinkat`. RFC 0086's table said otherwise and is corrected in
  place. A runtime that re-executes itself still needs the answer to be right.
- `ENOSYS` says the call does not exist, which is wrong twice over: `readlink` does, and the
  honest answer for a process with no known path is `ENOENT`.

## Design

1. **What is recorded, and where.** `Process` gains an `image` record, set by `execve`:
   - the path the program was exec'd from, at most `MAX_NAME` (64) bytes;
   - the address ranges of its argument and environment strings in its own new stack.

   `stack::Builder::string_ranges(base)` computes those ranges from the same layout `build`
   writes, and is host-tested against it. `fork` copies the record; a later `execve` replaces it.
   A process the kernel started has none.
2. **`cmdline` and `environ` are read from the process's own memory**, between those addresses,
   when the file is read. That is how Linux serves them, as recalled from its
   `proc_pid_cmdline_read` reading `arg_start..arg_end`. So a program that rewrites its argv
   changes its `cmdline` here too, as it would there. They are new `/proc` files beside `status`
   and `maps`, read-only and generated per read.
3. **`readlink(path, buf, size)` and `readlinkat(dirfd, path, buf, size)`:**
   - `/proc/self/exe` answers the recorded path, truncated to `size` with no terminator, which is
     `readlink`'s contract (`readlink(2)`: "does not append a null byte ... (silently) truncate");
   - with no record, the answer is `ENOENT`;
   - any other path keeps today's answer, so this RFC does not invent a symlink model it has not
     designed.
4. **`execve("/proc/self/exe")`** resolves to the recorded path: re-executing itself is what a
   program asks `/proc/self/exe` for. With no record the answer is `ENOENT`.
5. **The `/proc` rule holds.** The path is one the process's own `execve` named, in its own
   filesystem's terms, and the strings are its own. Nothing names a Bhaskix object.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Answer every process, inventing a path for one the kernel started (`/proc/self/exe` → `/bin/unknown`) | RFC 0005's rule: an invented path is the first thing this adapter would make up, and a program that re-executes it would exec nothing. | The kernel starts programs from paths of its own and says which. |
| Copy argv and the environment into the record at `execve` | Up to 2 KiB per process in a table of 32 that is already tens of kilobytes; and the copy would disagree with the program's memory once it rewrote its argv, which Linux's does not. A read from a range the program has since unmapped answers `EIO` here. | A program that relies on reading its original argv after unmapping its own stack. |
| Keep `ENOSYS` | It says the call does not exist. | Never. |

## Security implications

- **No new authority.** A process reads its own path and its own memory, and only about itself:
  `/proc/<pid>/` of another process stays unanswered (RFC 0033's rule).
- **The path is not a capability.** Knowing it grants nothing that `execve` of the same path did
  not already require.

## Testing plan

- **Host:**
  - `string_ranges` against `build`'s bytes;
  - the new `/proc` files and the `readlink` decision, including `ENOENT` with no record;
  - the leak test's rule extended to them.
- **QEMU:**
  - the hosted program, which `bin/linuxd` exec's as `/hosted one two` with
    `GREETING=namaste`, prints what `readlink` answered and whether `cmdline` and `environ` read
    back exactly `hosted\0one\0two\0` and `GREETING=namaste\0`;
  - the gate matches the whole line.
- **Armed:** `readlink` answering `ENOSYS` again.

## Unresolved questions

None. RFC 0005 decided the one question this could have had.

## Implementation plan

1. The image record, `string_ranges`, the `/proc` files and the `readlink` decision, host-tested.
   **Done 2026-10-31.**
2. `readlink`, `readlinkat`, the reads and `execve`'s substitution in `bin/linuxd`; the hosted
   program's line and its gate, armed. **Done 2026-10-31**: the hosted program reports `exe
   /hosted cmdline ok environ ok` on the `iommu` lane. **Armed twice**: `readlink` back at
   `ENOSYS` (`exe errno 38`), and the two ranges swapped (`cmdline BAD environ BAD`), each red
   with the gate's own message.
3. TRACKER §4's two rows; the guide's limits. **Done 2026-10-31.**
