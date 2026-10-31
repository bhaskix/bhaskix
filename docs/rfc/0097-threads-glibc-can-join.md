# RFC 0097: Threads glibc can join

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-10-31 by the project lead**, on CI run 893's green. Drafted, built and gated the same day. The one question decided by the lead the same day, as recommended (§*Unresolved questions*). Drafted at the lead's request. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`, `personality`) |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) |
| **Depends on** | [RFC 0086](0086-the-motivating-workload.md) (a thread that starts as Linux starts it), [RFC 0096](0096-a-fork-glibc-can-make.md) (which Linux tid each thread answers to) |

---

## Summary

A glibc program creates a thread with `clone(... | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)`
and waits for it with `pthread_join`, which is a futex wait on the thread's tid word. When the
thread exits, the kernel clears the word and wakes the waiter. This RFC makes the adapter do all
three:
- write the tid where `CLONE_PARENT_SETTID` names;
- clear the word and wake one waiter when the thread calls `exit`;
- answer the wait.

The wait is a *shared* futex, which the adapter has refused by design. As the lead decided, it is
now accepted and keyed to the caller's domain, like a private one.

## Motivation

**What glibc does, traced on the build host on 2026-10-31.** A static glibc 2.31 program creates
one thread and joins it. It was built in a scratch directory and is not part of the tree:

```
clone(child_stack=0x7f167964ee70, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tid=[2567616], tls=0x7f167964f700, child_tidptr=0x7f167964f9d0) = 2567616
[pid 2567615] futex(0x7f167964f9d0, FUTEX_WAIT, 2567616, NULL <unfinished ...>
[pid 2567616] set_robust_list(0x7f167964f9e0, 24) = 0
[pid 2567616] exit(0)                   = ?
<... futex resumed>)                    = 0
```

The same two facts, read the same day by disassembling the host's `libpthread.a`:
- `create_thread` passes `0x3d0f00`;
- `__pthread_clockjoin_ex` calls `futex` with operation `0`, a `FUTEX_WAIT` **without**
  `FUTEX_PRIVATE_FLAG`.

**What the adapter does with it today:**
- `plan_clone` accepts the flags, which are the thread shape plus `SETTLS` and the two tid flags.
- `clone::spawn` then drops both addresses.
- `plan_futex` refuses any operation without `PRIVATE` with `ENOSYS`
  (`personality/src/thread.rs`). Its note says a shared futex "would need a name for memory across
  domains, which is a capability, not an address".

So the tid word is never cleared, and the join's wait is refused.

**What glibc does when the wait is refused, also traced.** `strace -e inject=futex:error=ENOSYS`
on the same program shows glibc retrying the wait:
- **5,752 refused waits in the 200 ms the thread lived**, under `strace`, which slows each one;
- then `joined 0, returned 42`, once Linux cleared the word.

~~glibc treats a refused futex as fatal~~ -- **that claim was put to the lead from memory while
this RFC was planned, and the trace refutes it** for 2.31: glibc does not abort, it spins. Here,
where nothing clears the word, it would spin for ever, every turn a round trip to the adapter.

**Why nothing here noticed.** Go makes its own threads, with a flag set that carries neither tid
flag, and never joins one; BusyBox makes none. No program run here has made a thread through
glibc.

## Design

1. **`CLONE_PARENT_SETTID` for a thread.**
   - The new thread's tid is drawn from the pid space (RFC 0096).
   - It is written as a 4-byte word at the address the caller named, in the domain's memory,
     before the thread is started, so the creator finds it there when `clone` returns.
2. **`CLONE_CHILD_CLEARTID` for a thread**, recorded in the thread's `Threads` record, as
   `set_tid_address` already records it for a first thread.
3. **At a thread's `exit` (60):** if its record names an address, write 0 there and wake one
   waiter on it. This is Linux's thread-exit contract, as recalled from its `mm_release` and seen
   in the trace above: the join's wait returned 0 at the thread's `exit`.
   - An `exit_group`, or a fault that ends the domain, needs nothing: every thread that could be
     waiting ends with it.
4. **A futex without `PRIVATE` is keyed by (domain, address)**, exactly as a private one is. Every
   thread of a process runs in its domain, so `pthread_join` and anything else glibc does within
   a process works.
   - **The limit, stated:** a waiter in *another* domain on memory the two share is not woken by
     this domain's wake.
   - That is the case "a name for memory across domains" was about, and it stays unbuilt until
     its trigger: the first hosted program that waits on memory it shares with another process.
5. **The wake is one function**, `futex_wake(domain, address, count)`, shared by `FUTEX_WAKE` and
   the exit path.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Keep refusing shared futexes, build only the tid words | glibc then spins in `pthread_join` for the thread's whole life, a round trip to the adapter per turn: 5,752 refused waits in 200 ms under `strace`. | Never: the spin is the worst of both. |
| Name shared memory by capability (memory object and offset) | Correct across domains, as Linux is; a much larger RFC, and nothing hosted shares futex memory across processes yet. | The trigger in design item 4. |
| Clear the word without a wake | A joiner already parked would sleep for ever. | Never. |

## Security implications

- **No new authority.** The cleared word is in the memory of the domain whose thread named it, and
  the wake reaches only that domain's waiters.
- A shared futex keyed per domain cannot be used to signal another domain, which was the property
  the old refusal protected. It is kept by construction rather than by refusing.

## Performance implications

- One 4-byte write at a thread's creation.
- One 4-byte write and one wake at its `exit`.
- A `pthread_join` that parks once instead of spinning.

## Testing plan

- **Host:** `plan_futex` keys a shared wait and wake as it keys private ones.
- **QEMU:** a hand-assembled probe, `tools/probes/linux-thread-join.s`:
  - it clones with `0x3d0f00` and one word as both tid addresses;
  - it checks the word holds the new thread's tid at once;
  - it waits on the word with a shared `FUTEX_WAIT` until the thread's `exit` clears it.
  - The kernel's futex probe stops expecting a shared wait to be refused.
- **Armed** three ways:
  - no clear at `exit`;
  - no write for `CLONE_PARENT_SETTID`;
  - a shared futex refused again.

## Unresolved questions

1. **A shared futex: refuse it, key it to the domain, or name shared memory?** *Decided by the lead
   on 2026-10-31: keyed to the domain*, with the limit and trigger in design item 4.

**Recorded, not in scope:**
- `set_robust_list` and `rseq`, which glibc tolerates being refused.
- The vfork shape, which is RFC 0096's question 1.

## Implementation plan

1. `plan_futex` accepts a shared operation; the host test changes from refused to keyed.
   **Done 2026-10-31.**
2. `CLONE_PARENT_SETTID`, the cleared word and the wake at `exit`; the probe; the arms. **Done
   2026-10-31.** `linux join`: the word held the new thread's tid at once, and the creator parked
   once and was woken by the thread's `exit` -- `1 wait(s), the last answered 0`. **Armed three
   ways, each red alone:**
   - no clear at `exit`: the creator never finished;
   - no `CLONE_PARENT_SETTID` write: the word read 0 straight after `clone`, and the "join"
     returned at once with **0 waits** while the thread could still be running -- the hazard
     that write exists to prevent;
   - a shared futex refused again: **486 refused waits** (`-38`) until the thread's `exit`
     cleared the word -- glibc's spin, reproduced -- and the futex probe's shared wait read `-38`.
3. The kernel's futex probe; TRACKER; the guide's limits. **Done 2026-10-31**: the probe's shared
   `WAIT` expects 0 on a word of 1 and is answered `EAGAIN`, five bytes for the five `mov esi, 0`
   took.
