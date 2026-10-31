# RFC 0096: A fork glibc can make

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-30 — ~~nothing built~~ steps 1-4 built and gated 2026-10-31.** ~~Four questions for the lead~~ All four decided by the lead on 2026-10-31, each as recommended (§*Unresolved questions*). |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`, `personality`) |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — an interactive BusyBox `sh` runs a command that is not one of its builtins |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md) (what a hosted process is, and the child's register file it left open), [RFC 0084](0084-a-fork-the-kernel-copies.md) (the copy), [RFC 0094](0094-a-programs-vector-registers-are-its-own.md) step 3 (reading and writing a stopped thread's floating-point state) |

---

## Summary

Accept the `clone` that glibc's `fork()` makes, `CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID |
SIGCHLD` with no stack, and answer it with the fork this system already has, finished:
- the child starts with its parent's **whole** register file and floating-point state, and its
  thread-local base;
- the child's tid is written where the parent asked;
- `set_tid_address` is answered.

Then an interactive BusyBox `sh` can run `uname -a`.

## Motivation

**`/ # uname -a` answers `sh: can't fork: Function not implemented`** (TRACKER §3, filed
2026-10-19). Ubuntu's static BusyBox is linked against glibc. Its `fork()` is not system call 57.
Traced on the build host on 2026-10-30, with the pinned binary, running two commands so that the
first must fork:

```
set_tid_address(0x2a1b5690)             = 2327934
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x2a1b5690) = 2327935
[pid 2327935] execve("/bin/true", ["/bin/true"], ...) = 0
[pid 2327934] wait4(-1, ...)
```

The raw flags are `0x01200011`, and the stack, parent tid and TLS arguments are all zero.
`child_tidptr` is the address the program gave `set_tid_address` earlier, the thread's own tid
word. The child's first call goes through `%fs` (`set_robust_list(&self->robust_head)`), so it
needs its parent's TLS base before anything else runs.

**What answers it today:**
- **`plan_clone` refuses it by design.** `personality/src/thread.rs:80` accepts one shape, a
  thread sharing everything, and answers anything else `ENOSYS`.
- **`fork` (57) exists, but would not do.**
  - `answer_fork` (`user/linuxd/src/main.rs:7148`) makes a domain and copies the space eagerly
    (`COPY_SPACE`, RFC 0084).
  - It starts the child on a three-instruction trampoline: `rax` = 0, the parent's `rip` and
    `rsp`, **every other register zero**.
  - The TLS base and floating-point state are not carried, and `linuxd` cannot read a thread's TLS
    base back.

  RFC 0033 wrote this down: *"a fork that copies an address space correctly and hands the child a
  register file it should not have to accept … L2 is where that has to stop being true."* glibc
  makes that the present. Its inline `syscall` tells the compiler that only `rax`, `rcx` and `r11`
  change, so any other register can hold a live value across the call. That is the Linux system
  call ABI.
- **`set_tid_address` (218), `set_robust_list` (273) and `rseq` (334) are `ENOSYS`.**
- **No `SIGCHLD` is sent anywhere.** `wait4` works without it, by parking.

**Why the existing gate never saw this.** The BusyBox gate runs
`sh -c '/busybox echo bhaskix-busybox-forked'`. Its comment says the shell forks there. It does
not: a single command is exec'd directly, as the trace shows. The comment is corrected in this
draft's own change.

## Design

1. **A second accepted shape.**
   - **What `plan_clone` takes:** flags made only of the exit signal (the low byte) and
     `CHILD_SETTID`, `CHILD_CLEARTID` and `PARENT_SETTID`, with no sharing flags and no stack.
   - **What it answers:** `ClonePlan::Process { exit_signal, child_tid, parent_tid }`.
   - **Everything else is still refused**, a partial share included.
   - Host-tested, with glibc's exact flags as the first case.
2. **The fork, finished,** for this shape and for `fork` (57) alike:
   - **The child's general-purpose registers** are the parent's at the call, from the fault slot's
     image, with `rax` = 0. `thread::clone_trampoline` already restores a full set for threads.
   - **Its floating-point state** is the parent's, read and written with RFC 0094 step 3's calls.
   - **Its TLS base** is the parent's (question 3).
3. **`CHILD_SETTID`:** the child's tid is written at `child_tidptr` in the **child's** copy of
   memory, before it runs. `PARENT_SETTID` writes it in the parent's.
4. **`CHILD_CLEARTID`, recorded and not acted on, for a process.** It asks for the tid word to be
   zeroed and woken when the child's last thread ends. That word is in the child's own memory, which
   no one else maps, and is gone when the child ends or execs. *Not* so for threads:
   `pthread_join` waits on exactly that word. That is a separate gap, recorded below.
5. **`set_tid_address`** records the pointer and answers the caller's tid.
6. **Which number is the tid** (question 2): a process's first thread answers its pid, and any
   other thread a number drawn from the same space (`bhaskix_personality::thread::Threads`).

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Map glibc's shape onto `fork` (57) as it is | The child would run with `rbx`, `rbp`, `r12`–`r15`, its flags and its `%fs` zeroed. glibc's child touches `%fs` first. | Never; it would fail at its first instruction or, worse, later. |
| Accept any process-making `clone`, `CLONE_VM` and `CLONE_VFORK` included | A child sharing its parent's memory until it execs is a different object from a domain with its own space. | Question 1. |
| Answer `fork` from the kernel | The personality is in ring 3 by RFC 0032; the count of Linux calls the nucleus interprets is 0 and gated. | Never. |

## Security implications

- **No new authority.** A child gets what `fork` already gives it.
- **The register file, floating-point state and TLS base it starts with are its parent's, by
  definition.** That is the fork's contract, not a leak.
- **The tid write goes into memory the child owns, before it runs.**

## Performance implications

The same as `fork` today: an eager copy of the parent's space (RFC 0084). Plus one register-file
copy, one floating-point image (512–832 bytes), and one word written.

## Testing plan

- **Host:**
  - `plan_clone`'s new shape, and its refusals;
  - glibc's flags `0x01200011` as a literal case, so the test reads what the trace read.
- **QEMU:**
  - **BusyBox `sh -c '/busybox echo one; /busybox echo two'`.** The first command forks; both
    lines are printed and the child is collected.
  - **The interactive lane types `uname -a`**, which is what failed.
  - A hand-assembled probe forks with every register set to a known value and checks the child
    sees them, `rax` aside. That is the property the trampoline breaks today.
- **Armed:** the three-register trampoline in place of the full one turns the probe red.

## Unresolved questions

**All four decided by the lead on 2026-10-31, each as recommended**: the fork shape now and the
vfork shape when its trigger arrives; a first thread's tid is its pid; `linuxd` records the TLS
base; `SIGCHLD` later.

1. **Scope: glibc's fork shape only, or the vfork shape too?** *Recommended: the fork shape
   now.* Go's `os/exec` starts a child with `clone(CLONE_VFORK | CLONE_VM | SIGCHLD)`
   (`syscall/exec_linux.go:305-341`, Go 1.25.0, read on the build host). So a Go program that runs
   a subprocess needs the vfork shape, which shares memory until `execve` and wants an RFC of its
   own. Trigger: the first L1 program that runs one.
2. **Is a process's first thread's tid its pid?** On Linux it is. Here `gettid` answers the
   kernel's thread id plus one, so glibc's cached tid and `getpid()` disagree, and `raise()` sends
   with both. *Recommended: yes.* `linuxd` answers `gettid` with the pid for a process's first
   thread and gives other threads distinct numbers from the same space.
3. **Where the child's TLS base comes from.** *Recommended: `linuxd` records it* when it answers
   `arch_prctl(ARCH_SET_FS)` and `clone(CLONE_SETTLS)`. Those are the only two ways a hosted
   program sets it, because `CR4.FSGSBASE` is not enabled. The alternative is a kernel method to
   read a thread's base back.
4. **`SIGCHLD`: now or later?** Nothing sends it today, and `wait4` does not need it. An
   interactive shell's job control does. *Recommended: later*, with that as its trigger.

**Recorded, not in scope:**
- **`pthread_join`'s wait on `CLONE_CHILD_CLEARTID` for threads.** `linuxd` discards the thread
  tid addresses (`user/linuxd/src/main.rs:1006`).
- **`set_robust_list` and `rseq`.** glibc copes with `ENOSYS` from both.

## Implementation plan

1. `plan_clone`'s second shape and its tests. **Done 2026-10-31**: `ClonePlan::Process`, with
   glibc's `0x01200011` as the literal of the first test; a stack, any share, `CLONE_VFORK` or
   `CLONE_NEWPID` beside it is still `ENOSYS`. `CLONE_NEWPID`'s doc said it asked for a new process;
   it asks for a new pid *namespace* (`sched.h`, read on the build host), corrected in place.
2. The fork's full register file, floating-point state (after RFC 0094 step 3) and TLS base, for
   both entry points; the register probe, armed. **Done 2026-10-31**: the child starts on
   `clone_trampoline` with the staged frame's registers and the base `linuxd` recorded at
   `arch_prctl`; the parent's image is read from its slot at the fork and installed by `FP_WRITE` at
   the child's first call, which is always its trampoline's own (`arch_prctl` or `gettid`) and is
   asked for with its frame for that purpose. The probe (`tools/probes/linux-fork-registers.s`,
   `linux fork reg`): twelve general registers, the stack, the TLS base, `xmm0`-`xmm15` and
   `MXCSR`, **0 of 47 wrong**. **Armed twice**: the three-instruction trampoline back, and both
   children die of `SIGSEGV` through a zero TLS base and a zero `r15`; the image not installed,
   and **33 of 47** -- the 32 `xmm` quadwords and `MXCSR`, nothing else.
3. `CHILD_SETTID`/`PARENT_SETTID` and `set_tid_address`. **Done 2026-10-31**, with the tid
   numbering of question 2: the `linux futex` probe now reads `tid (36) and pid (36)`. The probe's
   `clone` child checks its tid is its pid and that the word it named holds it; the parent checks
   its own copy still holds `-1`. **Armed three times**, each red on its own bit: `gettid` back to
   the nucleus's number (`tid is not the pid`); the word not written (`the word does not hold
   it`); the word written in the parent's memory instead (the parent's word read `0x21`, the
   child's pid).
4. The BusyBox gates: two commands under `sh -c`, and `uname -a` typed. TRACKER's row closes.
   **Done 2026-10-31**, in two places, because building it found the planned one could not hold
   both:
   - **`uname -a` typed at the interactive shell** (`busybox-test.sh`) prints `Linux bhaskix
     3.2.0-bhaskix ... x86_64`, where it answered `sh: can't fork`. Typed as `/busybox uname -a` it
     answers `sh: /busybox: not found`: that lane's shell runs before the machine has a disk, on a
     machine without an IOMMU, so nothing is staged there.
   - **The two-command `sh -c`** runs on the `iommu` boot lane, which has a block service and now
     stages BusyBox (`bhaskix.busybox=1`, 2,190,672 bytes in 3,020 ms): the hosted program's
     `sh -c '/busybox echo bhaskix-busybox-first; /busybox echo bhaskix-busybox-forked'` prints
     both lines in order. That lane fails if nothing was staged, so the check cannot pass unasked.
   - **Armed**: with the fork shape refused again, both are red, and the logs say `sh: can't fork`.

**Found building it, and fixed in the same change.** The kernel's boundary instrument counted a
frame-needing call twice when its caller died between the question and the retry with the frame:
the first ask was counted as answered, and the failed retry then priced it as a call nobody
answered. The first boot of this change read `1036 of 1034 accounted`, with two callers killed --
probes that kill a child straight after forking it now catch the child in its first call, which
takes the frame path. The failed retry is answered `ENOSYS`, as it was, and not priced again:
`993 of 993` on the next boot. **The same mistake one line earlier, a frame that cannot be staged
because no slot is free, is left as it was** -- nothing here made it likelier -- and filed.
