#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every return to ring 3 hands a program its own registers or zeroes, never the kernel's.

## Why this exists

`enter_ring3` built its `iretq` frame from five values the compiler kept in
registers of its own choosing -- chosen *per inlined site* -- and set only `rdi`
and `rsi` for the program. At three of its sites the compiler put `cs` in `rdx`,
so a program entered there started with `rdx = 0x23`. The x86-64 process-entry
ABI makes `rdx` a termination function to register with `atexit`; glibc's
`_start` registered `0x23`, and RFC 0068's exec'd BusyBox `echo` called it on the
way out. Found 2026-09-28, after it had run unseen because no lane in `make
test` sets `bhaskix.busybox=1`.

It was not only `rdx`: every register the frame did not use reached ring 3 with
whatever the kernel last left in it, which is the wrong direction for a kernel
address to travel.

## The rule

For each `iretq`, look at the instructions after the last `push` before it --
the stretch where the frame is complete and only the register file is left to
settle. In that stretch, every one of the thirteen general-purpose registers a
program is not deliberately handed must be either

* **zeroed** -- `xor r, r`, in its 32- or 64-bit name -- the first entry into a
  program, which has no registers of its own yet; or
* **restored** -- `pop r` -- the return from an interrupt, which puts back the
  interrupted program's own.

`rdi` and `rsi` are excluded because `enter_ring3` hands a program its arguments
in them, explicitly, through register operands this text scan cannot see.

This needs no list of which `iretq` is which. `check-instruction-containment.py`
already confines every architecture instruction to `arch/`, so a new path into
ring 3 must appear here to exist, and must satisfy this to pass.

## Watched refusing

`--root tests/fixtures/ring3-entry` names a tree whose one `iretq` zeroes twelve
of the thirteen registers. The Makefile runs it and requires the refusal.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# The thirteen registers a program is not handed, by their 64-bit names.
REQUIRED = [
    "rax", "rbx", "rcx", "rdx", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

# 32-bit names, which is how a zeroing `xor` is usually spelled -- writing a
# 32-bit register clears the upper half, so `xor eax, eax` zeroes all of `rax`.
NARROW = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "ebp": "rbp",
    **{f"r{n}d": f"r{n}" for n in range(8, 16)},
}


def wide(name: str) -> str:
    return NARROW.get(name, name)


def instruction(line: str) -> str:
    """The instruction on a line, from an `asm!` string or `global_asm!` text."""
    text = line.split("//", 1)[0].strip()
    # `asm!` operands are string literals, one instruction each.
    literal = re.fullmatch(r'"([^"]*)",?', text)
    if literal:
        text = literal.group(1).strip()
    return text.lower()


def check_file(path: pathlib.Path) -> list[str]:
    problems = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        if instruction(line) != "iretq":
            continue
        settled = set()
        for back in range(number - 2, -1, -1):
            op = instruction(lines[back])
            if op.startswith("push"):
                break
            zeroed = re.fullmatch(r"xor\s+(\w+)\s*,\s*(\w+)", op)
            if zeroed and zeroed.group(1) == zeroed.group(2):
                settled.add(wide(zeroed.group(1)))
            popped = re.fullmatch(r"pop\s+(\w+)", op)
            if popped:
                settled.add(wide(popped.group(1)))
        missing = [reg for reg in REQUIRED if reg not in settled]
        if missing:
            problems.append(
                f"{path}:{number}: iretq hands ring 3 {', '.join(missing)} unset -- "
                "each must be zeroed or restored after the frame is pushed"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default="arch", help="tree to scan (default: arch)")
    options = parser.parse_args()

    root = pathlib.Path(options.root)
    sites = 0
    problems = []
    for path in sorted(root.rglob("*.rs")):
        found = check_file(path)
        problems.extend(found)
        sites += sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                     if instruction(line) == "iretq")

    if sites == 0:
        # A scan that finds nothing to check cannot report that everything
        # passed: that is exactly what a scanner reading the wrong tree says.
        print(f"  \033[1;31mFAIL\033[0m  no iretq found under {root}, so nothing was checked")
        return 1
    for problem in problems:
        print(f"  \033[1;31mFAIL\033[0m  {problem}")
    if problems:
        return 1
    print(
        f"  \033[1;32mok\033[0m    every return to ring 3 settles all thirteen registers "
        f"({sites} iretq site(s) under {root})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
