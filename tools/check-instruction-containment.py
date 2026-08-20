#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enforce where architecture-specific instructions may appear.

`docs/architecture.md` §7 commits to defining a portability boundary *before* a
second architecture exists, because retrofitting portability into a kernel that
assumed one architecture is a rewrite. Until 2026-08-20 that section claimed
"architecture-specific instructions appear only in `arch/`", and nothing checked
it — 40 `asm!` sites were in `arch/` and 20 were not. **The boundary was
described as a rule and enforced as a habit.** This is the gate that closes the
gap between those two sentences.

## The rule

A crate that contains architecture-specific instructions declares how many, in
`Cargo.toml` under `[package.metadata.bhaskix]`:

    asm_budget = 7

Exceeding the budget fails the build. **Containing instructions with no budget
declared fails the build**, which is the half that matters: a crate cannot grow
its first instruction quietly, and the list of crates that may contain any is
therefore the list of crates that declare one — a list a reviewer can read.

A crate at zero declares nothing. That is deliberate, and it is the difference
between this gate and `check-unsafe-budget.py`, which requires every crate to
declare: `unsafe` is expected everywhere and its *quantity* is the question,
while an instruction outside `arch/` is an exception and its *existence* is.
Twenty crates would otherwise carry `asm_budget = 0` to say nothing.

## The metric, stated because a metric nobody states gets misread

**Sites, not lines.** One `asm!` block is one site whether it holds one
instruction or thirty, because the reviewable question is "how many places in
this crate know what an x86 is", not "how many instructions do they emit". This
differs from the `unsafe` budget on purpose, which counts *lines inside* blocks;
`arch/x86_64/Cargo.toml` already states its own metric for the same reason.

Four forms count, and they are counted the same:

  * `asm!` and `core::arch::asm!`
  * `global_asm!` and `core::arch::global_asm!`
  * `naked_asm!` — none in the tree today; counted so the first one is visible
  * `core::arch::x86_64::…` intrinsics, which are architecture-specific without
    being assembly, and are the form a grep for `asm!` misses

**Comments are stripped before counting**, and this is not a nicety: the first
version of this survey counted `net/src/siphash.rs`, whose only match is the
sentence *"`bhaskix-rand` is two `asm!` blocks and a retry loop"* in a doc
comment. A budget inflated by prose is a budget that permits a real instruction
nobody declared.

**Test modules are stripped**, matching `check-unsafe-budget.py`'s reasoning:
test code does not ship, so counting it distorts the number the budget exists to
track. The helper below is deliberately a copy of that tool's rather than an
import — these two files are each meant to be readable alone, and `tools/` has
no package for them to share.

Usage:
    tools/check-instruction-containment.py            # check, non-zero on failure
    tools/check-instruction-containment.py --report   # print the table, exit 0
    tools/check-instruction-containment.py --root DIR # scan DIR (the negative arm)
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {"target", "build", "limine"}

# The negative fixture violates on purpose, so `make gates` can watch this tool
# go red. Scanning it during a normal run would make the gate unrunnable, which
# is how a gate loses the one test that proves it works — the same argument
# `check-deps.py` makes for the same reason.
SKIP_PATHS = ("tests/fixtures/",)

RED, GREEN, YELLOW, RESET = "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[0m"

# One site each. The `\b` on the macros keeps `naked_asm!` from also counting as
# `asm!`, and keeps an identifier ending in `asm` from counting at all.
FORMS = re.compile(
    r"(?<![A-Za-z0-9_])(?:core::arch::)?(?:global_asm|naked_asm|asm)!"
    r"|(?:core::)?arch::x86_64::[A-Za-z_]"
)


def _skipped(path: pathlib.Path, root: pathlib.Path) -> bool:
    """Skip build output, vendored code, dot-directories, and the fixtures."""
    if any(part in SKIP_DIRS or part.startswith(".") for part in path.parts):
        return True
    relative = path.relative_to(root).as_posix()
    return any(relative.startswith(prefix) for prefix in SKIP_PATHS)


def strip_comments(text: str) -> str:
    """Blank out line and block comments, preserving line structure.

    Newlines are kept so a reported line number still means something. Nesting
    is honoured because Rust's block comments nest, and a tool that stops at the
    first `*/` would resume counting inside a comment.
    """
    out, index, depth = [], 0, 0
    length = len(text)
    while index < length:
        if depth == 0 and text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            out.append(" " * (end - index))
            index = end
            continue
        if text.startswith("/*", index):
            depth += 1
            out.append("  ")
            index += 2
            continue
        if depth and text.startswith("*/", index):
            depth -= 1
            out.append("  ")
            index += 2
            continue
        character = text[index]
        out.append(character if (depth == 0 or character == "\n") else " ")
        index += 1
    return "".join(out)


def strip_test_modules(lines: list[str]) -> list[str]:
    """Blank out `#[cfg(test)] mod ... { ... }` blocks, keeping line numbers."""
    kept = list(lines)
    index = 0
    while index < len(kept):
        if "#[cfg(test)]" not in kept[index]:
            index += 1
            continue
        scan, depth, started = index, 0, False
        while scan < len(kept):
            depth += kept[scan].count("{") - kept[scan].count("}")
            started = started or "{" in kept[scan]
            kept[scan] = ""
            if started and depth <= 0:
                break
            scan += 1
        index = scan + 1
    return kept


def sites(path: pathlib.Path) -> list[int]:
    """The 1-based lines of `path` holding an instruction site."""
    text = strip_comments(path.read_text(errors="replace"))
    lines = strip_test_modules(text.splitlines())
    found = []
    for number, line in enumerate(lines, start=1):
        found.extend([number] * len(FORMS.findall(line)))
    return found


def crates(root: pathlib.Path) -> list[tuple[str, pathlib.Path, int | None]]:
    """Every crate under `root`, with its declared budget if it has one."""
    found = []
    for manifest in root.rglob("Cargo.toml"):
        if _skipped(manifest, root):
            continue
        text = manifest.read_text()
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
        if not name:
            continue  # a workspace root declares no crate
        budget = re.search(r"^\s*asm_budget\s*=\s*(\d+)", text, re.M)
        found.append((name.group(1), manifest.parent, int(budget.group(1)) if budget else None))
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the table and exit 0")
    parser.add_argument("--root", default=str(REPO), help="directory to scan")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()

    status = 0
    rows: list[tuple[str, int, int | None]] = []

    for name, directory, budget in crates(root):
        total = 0
        where: list[tuple[pathlib.Path, int]] = []
        for source in sorted(directory.rglob("*.rs")):
            if _skipped(source, root):
                continue
            for line in sites(source):
                total += 1
                where.append((source, line))

        if total:
            rows.append((name, total, budget))

        if total and budget is None:
            status = 1
            if not args.report:
                plural = "site" if total == 1 else "sites"
                print(f"{RED}FAIL{RESET}  {name}: {total} instruction {plural} and no asm_budget declared")
                for path, line in where:
                    print(f"        {path.relative_to(root)}:{line}")
                print("        Declare asm_budget under [package.metadata.bhaskix], with a")
                print("        comment saying why this crate must know what an x86 is.")
        elif budget is not None and total > budget:
            status = 1
            if not args.report:
                print(f"{RED}FAIL{RESET}  {name}: {total} instruction sites exceed budget {budget}")
                for path, line in where[budget:]:
                    print(f"        {path.relative_to(root)}:{line}")
        elif budget is not None and total < budget:
            # Lowering is the direction this number is supposed to move, so this
            # is a note rather than a failure — but an un-lowered budget is a
            # permission nobody is using, and permissions decay into holes.
            if not args.report:
                print(f"{YELLOW}note{RESET}  {name}: {total} sites, budget {budget} — lower it")

    if rows:
        print()
        print(f"  {'crate':<24} {'sites':>7} {'budget':>7}   headroom")
        print(f"  {'-' * 24} {'-' * 7} {'-' * 7}   {'-' * 8}")
        for name, total, budget in rows:
            if budget is None:
                print(f"  {name:<24} {total:>7} {'--':>7}   {RED}undeclared{RESET}")
                continue
            headroom = budget - total
            colour = GREEN if headroom >= 0 else RED
            print(f"  {name:<24} {total:>7} {budget:>7}   {colour}{headroom:+d}{RESET}")
        print()

    if status == 0 and not args.report:
        print(f"{GREEN}ok{RESET}    architecture-specific instructions are declared where they live")

    return 0 if args.report else status


if __name__ == "__main__":
    raise SystemExit(main())
