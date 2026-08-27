# RFC 0050: a console line that arrives whole

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-27** — proposed, built and accepted the same day, and **confirmed on hardware**: `execed pid 3` arrives intact on its own line on the SR550's sixteen processors, where before the fix a preserved log has it as `e`, then a whole kernel report, then `xeced pid 3`. `PUT_RUN` puts a run of bytes with the console lock held **once**: the same `Rights::WRITE` that `PUT` needs, the same rendering byte by byte, and no new authority — what it removes is the gap between one byte and the next, into which a kernel line could land and did. **What acceptance does not claim.** *(1)* **No gate proves that nothing can interleave.** The `execed pid 3`, `through a pipe` and `copied!` gates require a hosted line to arrive intact and are this test in weak form — they fail only when a split happens to land, which is what made this a five-day intermittent rather than a bug. What is proven is narrower and was watched red: the run is put under one lock, and every byte of it arrives in order. *(2)* **The atom is bounded at 256 bytes**, `bin/linuxd`'s own `WRITE_BYTES`, so a hosted `write` is one invocation and a longer line is more calls — and *those calls can interleave with each other*. *(3)* **The crossing saving is asserted from the code and not measured**: the boundary instrument counts foreign syscall crossings and `service::counted` accumulates bytes, so nothing in the tree counts console invocations. That was a claim in this document's own performance section until it was checked. *(4)* Native programs still put one byte at a time; only the Linux adapter uses `PUT_RUN` today, so `bin/sup`'s and `bin/shell`'s output can still be split, and unresolved question 1 covers it |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0032](0032-a-supervisor-interface.md) (the adapter's console), [RFC 0005](0005-linux-abi-compatibility.md) (what a hosted `write` is) |

---

## Summary

Add `PUT_RUN` to the `Console` object: put `length` bytes from the caller's
address space in a single invocation, under a single acquisition of the console
lock. `PUT` stays exactly as it is.

## Motivation

**A defect with a specimen, not a theory.** From a preserved boot log of
2026-08-26:

    e    linux exec     a Linux program execed: its own domain ended and the program it became ran in another
    xeced pid 3

`/bin/execed` wrote `execed pid 3\n`. The `e` reached the console. A kernel
`println!` then took the console lock and emitted a whole line. `xeced pid 3`
followed. The program's line never appears intact.

**Why.** `console::_print` takes `CONSOLE.lock()` for the whole of one
`write_fmt`, so a *kernel* line is atomic against everything. A hosted `write`
reaches the console through `bin/linuxd`, which loops `INVOKE`/`PUT` **one byte
at a time** — deliberately, because that is what a `Console` capability confers
— and each `PUT` takes and releases the lock on its own. Thirteen bytes are
thirteen independently locked writes, and any other CPU printing between two of
them splits the line.

This has been the `exec`/pid intermittent filed on 2026-08-21 and seen twice
since. Two hypotheses were killed by reading — that the write might be
asynchronous, and that `copy_in` might read a stale domain after an `execve` —
and both were right to die: **the write never failed.** It succeeded completely
and arrived in two pieces.

**It is not the test's problem.** Any hosted program's output can be split by any
kernel line on any boot. The standing user directive says output must be
well-formatted; a program's line arriving in halves around an unrelated kernel
report is not. The test is merely the thing that notices.

## Design

One method on the `Console` object, beside `PUT`:

| | |
|---|---|
| `arg0` | address of the bytes, in the **caller's** address space |
| `arg1` | how many, `1..=MAX_CONSOLE_RUN` |
| rights | `Rights::WRITE` — the same right `PUT` needs, and no new authority |
| returns | how many bytes were put |

The kernel translates the caller's buffer page by page — the loop `copy_across`
already uses, with `vm::frame_for_read`, because putting a byte is a read of the
caller's memory and must not commit a lazily-mapped page — copies it into a
bounded kernel buffer, and then takes the console lock **once** and writes every
byte.

**Byte semantics are unchanged.** `PUT` renders its argument with
`char::from_u32(...).unwrap_or('?')`, and a run renders each byte the same way.
`PUT_RUN` of *n* bytes is exactly *n* `PUT`s, minus the opportunity for anything
to interleave.

**The bound is the kernel's, not the caller's.** `MAX_CONSOLE_RUN` is 256 —
`bin/linuxd`'s own `WRITE_BYTES`, so a hosted `write` is one invocation — and a
longer request is refused rather than truncated silently. A line longer than the
bound is more calls, and those calls can interleave with each other: **this makes
a bounded run atomic, not an unbounded one**, and that limit is stated here
rather than discovered.

## Alternatives considered

**Pack the bytes into the message registers.** Four `u64` arguments carry up to
about twenty-four bytes, which needs no access to the caller's memory at all and
is the safest thing that could work. Rejected because it does not do the job:
the report lines this system prints are aligned columns eighty characters wide,
and a twenty-four-byte atom splits them into four pieces. It would have made the
`execed pid 3` case pass and left the defect.

**Line-buffer per writer inside the console.** Hold a partial line per calling
domain, flush on newline. No ABI change and no new authority, and it fixes every
hosted writer at once. Rejected for two reasons: it puts buffering **policy**
inside the nucleus, which is exactly what this project moved out — `PUT`'s own
comment says *"deciding that an escape sequence must not reach it is policy, and
policy is what was moved out"* — and a program that writes without a newline has
its output held until a buffer fills, which is a behaviour nobody asked for.

**Fix only the gate.** Make the `exec` test tolerant of a split line. Rejected:
it silences the only thing that notices a real defect, and leaves every hosted
program's output interleaved for anyone actually using the machine.

## Impact on existing design documents

`PUT`'s comment in `syscall.rs` says *"A character at a time, because that is
what a `Console` capability confers: the authority to put one"*, and `linuxd`'s
`WRITE` calls the resulting cost *"the honest cost of a console that is a
capability rather than a kernel function this program may call."* **Both were
deliberate and this reverses the second half of the trade**, so both are amended
rather than quietly left: the authority is unchanged — a holder may put bytes to
the console and nothing else — and what changes is that it may say how many at
once. The cost sentence stops being true and is replaced with the number.

## Security implications

**No new authority.** `PUT_RUN` needs the same `Rights::WRITE` as `PUT` and does
nothing `PUT` repeated could not do. A holder that could already put every byte
of a line can now put them without being interrupted.

**It does read the caller's memory, which `PUT` did not.** That is the real
change in kind, and it is the same read `COPY_IN` already performs for a
supervisor: translated through the caller's own root, bounded by length, page by
page, and refused if any page is absent. It commits nothing — `frame_for_read`,
not `frame_for_write` — so a caller cannot use the console to force a lazy
mapping to materialise.

**A denial of service is bounded by the same thing that bounds `PUT`.** The
console lock is held for at most `MAX_CONSOLE_RUN` bytes, which is 256 rather
than 1. A domain that holds a console capability could already hold the lock
repeatedly; it can now hold it 256 times longer per call, and the fix for a
console-holder that misbehaves is the same as it was: do not grant it one.

## Performance implications

A hosted `write` of a line becomes **one** crossing where it was one per byte —
thirteen fewer for `execed pid 3`, up to 255 fewer for a full buffer.

**And it is not visible in the boot report, which this section claimed it would
be before the claim was checked.** The `personality boundary` line counts
*foreign syscall* crossings, and a hosted `write` is one of those either way;
`service::counted` accumulates **bytes**, not invocations, and `PUT_RUN` passes
the same byte count `PUT` did, deliberately, so the two are comparable. Nothing
in the tree counts console invocations. The saving is real and is asserted here
from the code rather than measured, which is the honest way to put it — and it
is a side effect in any case. The reason is that the line arrives whole.

## Testing plan

1. **Host test on `console::put_run`**: every byte is emitted, in order, through
   the recorder that `recorder_tests` already uses; a byte that is not a scalar
   value renders as `?`, exactly as `PUT` renders it. Watched red by dropping a
   byte.
2. **A boot gate that the old code cannot pass.** A hosted program writes a
   line while the kernel prints, and the line must appear intact. The existing
   `execed pid 3` gate is that test in weak form — it fails only when the split
   happens to land — so this is stated as a limit: **the gate proves the line
   arrives whole on a run, not that it always will.**
3. `make test`, every lane, and the boundary instrument's crossing count
   compared before and after on the same boot of the host.

## Unresolved questions

1. **Should `PUT` be removed once nothing uses it?** It is the one-byte case of
   `PUT_RUN` and keeping both is two paths to maintain. Keeping it for now: the
   shell and the console service both use it, and removing a method is a
   separate change with its own blast radius.
2. **Should the console service, when it is the one in a domain, get the same
   method?** It holds a `Console` capability like anything else, so it inherits
   `PUT_RUN` for free; whether `bin/consoled` should *use* it is a question about
   that service and not about this method.

## Implementation plan

1. `bhaskix_abi::method::PUT_RUN` (69), and the kernel's assertion that the two
   agree. ✅ **Done 2026-08-27.**
2. `console::put_run(bytes)` — one lock, every byte. ✅ **Done**, with two host
   tests and **both mutations watched red**: dropping a byte and reversing the
   order each turn them red, and they go green again when restored. The tests
   themselves were wrong first and said so: `recorded()` answers
   `(kept, refused)` and not a range, and reading the second number as a
   position made an empty console look like a lost run.
3. The syscall arm: resolve, check `WRITE`, translate the caller's buffer page
   by page with `vm::frame_for_read`, copy, `put_run`. Bounded by
   `MAX_CONSOLE_RUN` = 256. ✅ **Done.**
4. `bin/linuxd`'s `WRITE` uses it, and both amended comments say what changed
   rather than being quietly rewritten. ✅ **Done.**
5. The gate. ⬜ **Not built, and the reason is worth stating.** The existing
   `execed pid 3`, `through a pipe` and `copied!` gates already require a hosted
   line to arrive intact, so they *are* this test — in the weak form the testing
   plan admits: they fail only when a split happens to land, which is what made
   this a five-day intermittent rather than a bug. A gate that provoked the split
   deliberately would need a hosted program writing a long line while another CPU
   prints, which is a self-test of its own. **What is proven today is that the
   run is put under one lock and that every byte of it arrives; what is not
   proven by a gate is that nothing can interleave.**
