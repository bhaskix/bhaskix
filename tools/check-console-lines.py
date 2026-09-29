#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every line a ring-3 program writes to the console fits in one console run.

## Why this exists

The console service keeps a caller's line whole only up to `LINE_BYTES`, which
is the nucleus's `MAX_CONSOLE_RUN` -- 256 bytes. A longer line goes out as two
runs, and another CPU's print can land between them. On 2026-09-29 one did:
`bin/sup`'s gated report line was 329 bytes, a kernel line landed at exactly
byte 256, and `the supervisor interface did not hold` failed a boot on which
everything it tests had held. Nothing had asked whether that line fitted.

## The rule

In every `.rs` file under `user/*/src`, each line of each byte-string literal (`b"..."`),
after Rust's `\\`-newline continuation is applied, is at most `MAX_CONSOLE_RUN`
bytes including its newline. The limit is read from `kernel/src/syscall.rs`, so
the two cannot drift apart.

## What it cannot see

A line assembled at run time from several `write` calls -- a literal, then a
number, then another literal -- is invisible to a text scan. Those stay the
writer's to keep short, and a gate on such a line should not need it whole.

## Watched refusing

`--root tests/fixtures/console-lines` names a tree holding one literal line
over the limit. The Makefile runs it and requires the refusal.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
LIMIT_SOURCE = HERE.parent / "kernel" / "src" / "syscall.rs"
LITERAL = re.compile(r'b"((?:[^"\\]|\\.)*)"', re.S)


def limit() -> int:
    text = LIMIT_SOURCE.read_text(encoding="utf-8")
    found = re.search(r"const MAX_CONSOLE_RUN: usize = (\d+);", text)
    if not found:
        raise SystemExit(f"MAX_CONSOLE_RUN not found in {LIMIT_SOURCE}")
    return int(found.group(1))


def lines_of(literal: str) -> list[str]:
    # Rust drops a backslash-newline and the whitespace after it.
    joined = re.sub(r"\\\n\s*", "", literal)
    return joined.replace("\\n", "\n").split("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default="user", help="tree to scan (default: user)")
    options = parser.parse_args()
    most = limit()

    root = pathlib.Path(options.root)
    files = sorted(root.glob("*/src/**/*.rs"))
    problems = []
    literals = 0
    for path in files:
        source = path.read_text(encoding="utf-8")
        for match in LITERAL.finditer(source):
            literals += 1
            for line in lines_of(match.group(1)):
                # A line that ends the literal without a newline is still
                # written; count the newline only where there is one to come.
                size = len(line.encode("utf-8")) + 1
                if size > most:
                    at = source[: match.start()].count("\n") + 1
                    problems.append(
                        f"{path}:{at}: a {size}-byte console line, past the {most} the console "
                        f"keeps whole: {line[:60]}..."
                    )

    if literals == 0:
        # A scan that finds nothing to check cannot report that everything
        # passed: that is exactly what a scanner reading the wrong tree says.
        print(f"  \033[1;31mFAIL\033[0m  no byte-string literal found under {root}, so nothing was checked")
        return 1
    for problem in problems:
        print(f"  \033[1;31mFAIL\033[0m  {problem}")
    if problems:
        return 1
    print(
        f"  \033[1;32mok\033[0m    every console line under {root} fits in one {most}-byte run "
        f"({literals} literals in {len(files)} files)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
