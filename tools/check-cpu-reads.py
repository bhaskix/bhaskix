#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every read of "which CPU is this" in the kernel says why a migration cannot split it.

## Why this exists

A kernel thread with interrupts on can be preempted and resumed on another CPU
between any two instructions. So `percpu::cpu_id()` followed by anything that
acts on *that CPU's* state -- its runqueue's `current`, its held-lock mask, its
frame reserve, its domain note -- is two instants, and a thread that moved
between them acts on a CPU it has left.

On 2026-09-28 that shape was found in **ten functions**, every one of them
after it had shipped -- the last two by writing this gate:

* `sched::current_thread_id` answered with another thread's id -- the ring
  self-test's wedge, caught in the act by CI run 761;
* `sched::current_domain`, which names the capability table a syscall
  resolves its index in, and `exit`, `should_die`, `cancel_block`;
* `sync`'s `lock()`, which checked lock order against another CPU's mask --
  the lock-order row's four CI sightings;
* `frames::with_reserve`, which read the CPU before masking interrupts in
  `unsafe` code;
* the system-call entry, which read the caller's domain -- its dialect, and
  the hosted process `bin/linuxd` is told is calling -- after re-enabling
  interrupts.
* `sched::preempt_reporting`, which chose the queue to switch on from a CPU
  read before masking -- reached from `yield_now` with interrupts on, where a
  moved thread would have made another CPU's scheduling decision;
* `sched::check_user_space` on the system-call exit, which could compare
  another thread's address space with this CPU's and fail the boot test.

None was hard to fix. What they had in common is that nothing asked, at the
line, *why this read cannot be split*. This asks.

## The rule

Every non-test line in `kernel/src` that calls `cpu_id()` must have, in the
comment block directly above it (or trailing on the same line), a comment

    // CPU: <tag> -- <reason>

where `<tag>` is one of:

* `masked`     -- interrupts are off here, so nothing can move the thread;
* `interrupt`  -- this runs in an interrupt or exception handler (the gate
                  cleared `IF`);
* `held`       -- the caller holds a ranked lock, and `preempt` will not
                  switch a lock holder out;
* `rechecked`  -- the CPU is read again under the lock it chose, and the
                  answer is only used when the two agree;
* `pinned`     -- the thread is pinned to its CPU;
* `boot`       -- this runs before any other CPU or the scheduler does;
* `caller`     -- this function is only correct if its caller cannot move,
                  and its doc comment says which of the above the caller
                  must supply;
* `hint`       -- a wrong CPU costs latency or a wasted IPI, never
                  correctness;
* `diagnostic` -- a wrong CPU mislabels a report and decides nothing;
* `any`        -- the result is correct whichever CPU is read (a lookup by
                  thread id under a lock, say).

A tag is a claim a reviewer can check against the code beneath it; a missing
one is a read nobody has thought about.

## Watched refusing

`--root tests/fixtures/cpu-reads` names a tree with one annotated read and one
bare one. The Makefile runs it and requires the refusal.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

TAGS = (
    "masked", "interrupt", "held", "rechecked", "pinned", "boot",
    "caller", "hint", "diagnostic", "any",
)
TAG = re.compile(r"//\s*CPU:\s*(\w+)")
# How far above a read its justification may sit, through comments and the
# lines of one multi-line statement. Stops at a blank line.
REACH = 8


def code_part(line: str) -> str:
    """The line with any trailing `//` comment removed."""
    return line.split("//", 1)[0]


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("//")


def reads(lines: list[str]) -> list[int]:
    """Indices of lines that call `cpu_id()` in code, before any test module."""
    found = []
    for index, line in enumerate(lines):
        if line.startswith("mod tests") or (
            line.strip() == "#[cfg(test)]"
            and index + 1 < len(lines)
            and lines[index + 1].startswith("mod tests")
        ):
            break
        if not is_comment(line) and "cpu_id()" in code_part(line):
            found.append(index)
    return found


def justification(lines: list[str], index: int) -> str | None:
    """The tag justifying the read on `lines[index]`, or None."""
    trailing = TAG.search(lines[index])
    if trailing:
        return trailing.group(1)
    for back in range(index - 1, max(index - 1 - REACH, -1), -1):
        line = lines[back]
        if not line.strip():
            return None
        tag = TAG.search(line)
        if tag and is_comment(line):
            return tag.group(1)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default="kernel/src", help="tree to scan (default: kernel/src)")
    options = parser.parse_args()

    root = pathlib.Path(options.root)
    problems = []
    counted: dict[str, int] = {}
    sites = 0
    for path in sorted(root.rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index in reads(lines):
            sites += 1
            tag = justification(lines, index)
            if tag is None:
                problems.append(
                    f"{path}:{index + 1}: reads the CPU with no `// CPU: <tag>` saying why a "
                    "migration cannot split it"
                )
            elif tag not in TAGS:
                problems.append(
                    f"{path}:{index + 1}: `// CPU: {tag}` is not one of {', '.join(TAGS)}"
                )
            else:
                counted[tag] = counted.get(tag, 0) + 1

    if sites == 0:
        # A scan that finds nothing to check cannot report that everything
        # passed: that is exactly what a scanner reading the wrong tree says.
        print(f"  \033[1;31mFAIL\033[0m  no cpu_id() read found under {root}, so nothing was checked")
        return 1
    for problem in problems:
        print(f"  \033[1;31mFAIL\033[0m  {problem}")
    if problems:
        return 1
    tally = ", ".join(f"{counted[tag]} {tag}" for tag in TAGS if tag in counted)
    print(
        f"  \033[1;32mok\033[0m    every CPU read under {root} says why a migration cannot "
        f"split it ({sites}: {tally})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
