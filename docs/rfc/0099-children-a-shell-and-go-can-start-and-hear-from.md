# RFC 0099: Children a shell and Go can start and hear from

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-11-01 by the project lead**, on CI run 895's green. Drafted 2026-10-31, built and gated the same day. Its three questions decided by the lead that day, each as recommended (§*Unresolved questions*). |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`, `personality`), and one branch of the kernel's adapter call |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) |
| **Depends on** | [RFC 0096](0096-a-fork-glibc-can-make.md) (the fork this finishes; its questions 1 and 4 are this RFC), [RFC 0083](0083-a-signal-a-process-can-catch.md) (delivery to a handler), [RFC 0033](0033-what-a-hosted-process-is.md) (`wait4`) |

---

## Summary

The two things RFC 0096 left for later:
- **The vfork shape**, which Go's `os/exec` uses to start every program, is answered as a copying
  fork that **holds the parent until the child execs or ends**, vfork's promise kept without
  sharing memory.
- **`SIGCHLD`** reaches a parent that installed a handler when a child ends. A parent that set it
  to `SIG_IGN` has its children reaped for it, as Linux does.

Building it found that **`SIG_IGN` was read as a handler at address 1**, for every signal, and that
is fixed in the same change.

## Motivation

**Go starts a program with a vfork.** Go 1.27.1's `syscall/exec_linux.go`, read in the pinned
toolchain on 2026-10-31, passes `flags |= CLONE_VFORK | CLONE_VM` (`:309`) and `| SIGCHLD`
(`:338`) through `rawVforkSyscall` with no stack:
- `plan_clone` refused it, so a Go program here could not run another program.
- `CLONE_PIDFD` is added only when Go's `checkPidfd` succeeded (`os/pidfd_linux.go`). That starts
  with `pidfd_open`, which is answered `ENOSYS` here, so Go never asks for one.

**A shell's job control waits on `SIGCHLD`.** Nothing sent one, and `wait4` worked without it by
parking.

**`SIG_IGN` was a handler at address 1.**
- `Dispositions::handler` read `entry != 0`, and `SIG_IGN` is 1.
- A process that ignored `SIGTERM` and was sent one had it made pending, and delivery would have
  jumped to 1.
- With no handler, `raise` falls back to the default, which here means ending the process. That is
  right for `SIGTERM` and wrong for `SIGCHLD`, whose default is to be ignored.

## Design

1. **The vfork shape** (`plan_clone`): `CLONE_VFORK`, with or without `CLONE_VM`, plus the exit
   signal and the three tid flags, and no stack.
   - It becomes `ClonePlan::Process { hold: true, .. }`.
   - `CLONE_VM` alone is still refused: a sharer with no hold is nothing either honours.
   - So are a stack, any other share, and `CLONE_PIDFD`.
2. **Copy and hold** (the lead's choice). The child is RFC 0096's fork: a copied space, the whole
   register file, the floating-point state and the TLS base. The parent's `clone` is answered in
   two parts:
   - the first builds and starts the child, and parks the parent;
   - the child's successful `execve`, or its end however it comes, lets the parent go;
   - the parent's retry answers the child's pid.

   Go's child writes only its own stack frame before it execs, and the copy keeps that from the
   parent; the hold is what is left of vfork's contract to honour. The cost is a copy of the space
   per program started.
3. **The kernel's frame path parks.** A `clone` is answered with its register frame, and that
   path honoured only a value or a restore. It now honours `BLOCK_ON_RETRY` as the main path does:
   - the frame goes back and the thread parks;
   - the whole call is asked again, which stages a fresh frame.

   The park is one function, `park_for_retry`, shared by both paths.
4. **`SIGCHLD`** (the lead's choice: a handler, and `SIG_IGN`).
   - Each child records the exit signal its parent is sent: 17 for `fork` and a vfork, the
     `clone`'s low byte otherwise.
   - When it ends, `on_child_end` decides:
     - **a handler** has the signal raised and the parent woken if parked;
     - **`SIG_IGN` on `SIGCHLD`** reaps the child at once, so `wait4` finds no such child, as Linux
       does (recalled from its `do_notify_parent`);
     - **the default** does nothing; `SIGCHLD`'s default is to be ignored.
   - A child killed from outside is told the same way.
5. **`SIG_IGN` honoured, for every signal.**
   - `handler` counts only addresses above 1.
   - `disposition` answers Default, Ignore or Handler.
   - `kill`, at another process or at itself, ends nothing that ignores the signal, and counts it
     delivered without counting it raised, so the boot's raised-minus-delivered figure stays true.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Share the parent's memory (a true vfork) | Needs one address space in two domains, a new kernel mechanism, for a semantics Go's child does not use before it execs. | A program whose vfork child writes memory its parent reads. |
| Copy, and do not hold | Simplest, and breaks vfork's promise that the parent waits. | Never, now that the hold is built. |
| `SIGCHLD` to a handler only, `SIG_IGN`'s reap later | Leaves a parent that asked for no zombies holding them. | -- |

## Security implications

- **No new authority.** A child is what `fork` already made, and a parent hears only of its own
  children.
- **`SIG_IGN` read as an address was a jump to 1** in a process that asked to ignore a signal.
  Fixed, and held by a host test that is red on the old rule.

## Testing plan

- **Host:**
  - the vfork shape (`0x4111` as a literal) and its refusals;
  - `disposition` and `SIG_IGN`;
  - `on_child_end`.
- **QEMU:** `tools/probes/linux-vfork-sigchld.s`, `linux vfork`:
  - a vfork with Go's flags whose child yields and exits with 7, and the parent's
    `wait4(pid, WNOHANG)` at once must collect it;
  - the handler must have run once;
  - under `SIG_IGN` a forked child must reap itself, so `wait4(-1)` answers `ECHILD`;
  - `kill(self, SIGTERM)` under `SIG_IGN` must leave the process running.
- **Armed** four ways.

## Unresolved questions

**All three decided by the lead on 2026-10-31, each as recommended:**
1. **vfork: copy and hold**, not shared memory, and not a copy with no hold.
2. **`SIGCHLD`: to a handler, and `SIG_IGN`'s reap**, not a handler alone.
3. **Drafted and built in one batch.**

**Recorded, not built:**
- An exit signal other than `SIGCHLD` reaches a handler and nothing else; its default (to end the
  parent) is not acted on.
- A real Go `os/exec` run waits for a Go program in the corpus that starts one.
- `SA_NOCLDWAIT`.

## Implementation plan

1. The shape, `disposition`, `on_child_end` and the exit signal, host-tested. **Done 2026-10-31**,
   the `SIG_IGN` test red on the old `entry != 0`.
2. The hold, the frame path's park, `SIGCHLD` at a child's end, `SIG_IGN` at `kill`; the probe.
   **Done 2026-10-31**: `linux vfork` on its first boot. **Armed four ways, each red alone:**
   - no hold: `WNOHANG` answered 0, the child still running;
   - no `SIGCHLD`: the handler ran 0 times;
   - no reap: `wait4` under `SIG_IGN` collected pid 29 instead of `ECHILD`;
   - `SIG_IGN` not honoured at `kill`: the probe was ended before it finished.
3. **Found building it:** a reference to the global `_start` in a probe assembles as a zero
   displacement and a relocation, which `tools/probe-bytes.sh` copied without applying. The
   handler would have written into its own code. A local label fixed the probe, and the tool now
   refuses an object with relocations; every probe in the tree passes it.
