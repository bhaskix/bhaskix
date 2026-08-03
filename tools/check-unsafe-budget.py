#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enforce the per-crate `unsafe` budget and the `// SAFETY:` rule.

Rust removes memory-safety bugs from safe code. It does not remove them from
`unsafe` code, and a kernel needs `unsafe`. So we manage it as a measured
quantity rather than pretending it away (docs/coding-style.md §3):

  1. Every crate declares `unsafe_budget` in Cargo.toml under
     [package.metadata.bhaskix]. Exceeding it fails the build.
  2. Every `unsafe` block carries a `// SAFETY:` comment. A block without one
     is a hard failure, not a lint.

The point is not to make `unsafe` impossible. It is to make its growth
*visible*, because the failure mode is gradual and invisible: no single PR
adds much, and a year later the auditable surface is the whole kernel.

Usage:
    tools/check-unsafe-budget.py            # check, exit non-zero on failure
    tools/check-unsafe-budget.py --report   # print the table and exit 0
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {"target", "build", "limine"}


def _skipped(path: pathlib.Path) -> bool:
    """Skip build output, vendored code, and any dot-directory."""
    return any(part in SKIP_DIRS or part.startswith(".") for part in path.parts)

RED, GREEN, YELLOW, RESET = "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[0m"


def crates() -> list[tuple[str, pathlib.Path, int | None]]:
    """Every workspace crate, with its declared budget."""
    found = []
    for manifest in REPO.rglob("Cargo.toml"):
        if _skipped(manifest):
            continue
        text = manifest.read_text()
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
        if not name:
            continue  # workspace root
        budget = re.search(r"^\s*unsafe_budget\s*=\s*(\d+)", text, re.M)
        found.append((name.group(1), manifest.parent, int(budget.group(1)) if budget else None))
    return sorted(found)


def scan(source: str) -> tuple[int, list[int]]:
    """Return (lines inside unsafe blocks, line numbers missing // SAFETY:).

    Deliberately a line scanner, not a parser. A real parse would be more
    precise about string literals and macros, but the numbers only have to be
    stable and comparable between commits -- and a scanner that anyone can
    read is worth more here than one that is exactly right.
    """
    lines = source.splitlines()
    unsafe_lines = 0
    missing: list[int] = []
    depth = 0

    for index, line in enumerate(lines):
        stripped = line.strip()

        if depth > 0:
            unsafe_lines += 1
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                depth = 0
            continue

        # `unsafe fn`, `unsafe trait`, `unsafe impl` are declarations, not
        # blocks: the danger they carry is documented in their `# Safety`
        # doc section, which rustdoc's missing-docs lint already enforces.
        if re.search(r"\bunsafe\s*\{", stripped) and not stripped.startswith("//"):
            # Look back through the contiguous comment block above the
            # block. A SAFETY justification worth reading is usually several
            # lines long, and the marker is on the first of them -- so this
            # must scan the whole comment, not just the line immediately
            # above. Blank lines and attributes are skipped so a comment above
            # a `#[allow]` still counts.
            found_justification = False
            for back in range(index - 1, max(-1, index - 25), -1):
                previous = lines[back].strip()
                if not previous or previous.startswith("#["):
                    continue
                if previous.startswith("//"):
                    if "SAFETY:" in previous:
                        found_justification = True
                        break
                    continue
                # A line of code. Keep scanning only if it cannot have ended a
                # statement -- rustfmt often wraps a long `let x: T =` across
                # lines, putting code between the comment and its `unsafe`
                # block. Stopping there would reject a justification that is
                # plainly present, so the scan continues past continuations
                # and stops at a real statement boundary.
                if previous.endswith((";", "{", "}")):
                    break
            if not found_justification:
                missing.append(index + 1)

            unsafe_lines += 1
            depth = line.count("{") - line.count("}")
            if depth < 0:
                depth = 0

    return unsafe_lines, missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the table, always exit 0")
    args = parser.parse_args()

    status = 0
    rows = []

    for name, directory, budget in crates():
        total = 0
        all_missing: list[tuple[pathlib.Path, int]] = []

        for source_file in sorted(directory.rglob("*.rs")):
            if _skipped(source_file):
                continue
            count, missing = scan(source_file.read_text())
            total += count
            all_missing += [(source_file, line) for line in missing]

        rows.append((name, total, budget))

        if all_missing and not args.report:
            print(f"{RED}FAIL{RESET}  {name}: unsafe block without a // SAFETY: comment")
            for path, line in all_missing:
                print(f"        {path.relative_to(REPO)}:{line}")
            status = 1

        if budget is None:
            if not args.report:
                print(f"{RED}FAIL{RESET}  {name}: no unsafe_budget declared in Cargo.toml")
                status = 1
        elif total > budget and not args.report:
            print(f"{RED}FAIL{RESET}  {name}: {total} unsafe lines exceeds budget {budget}")
            print("        Raising the budget is allowed, but the PR description must")
            print("        say why the new unsafe could not be avoided.")
            status = 1

    print()
    print(f"  {'crate':<24} {'unsafe':>7} {'budget':>7}   headroom")
    print(f"  {'-' * 24} {'-' * 7} {'-' * 7}   {'-' * 8}")
    for name, total, budget in rows:
        if budget is None:
            print(f"  {name:<24} {total:>7} {'--':>7}   {YELLOW}undeclared{RESET}")
            continue
        headroom = budget - total
        colour = GREEN if headroom >= 0 else RED
        print(f"  {name:<24} {total:>7} {budget:>7}   {colour}{headroom:+d}{RESET}")
    print()

    if status == 0 and not args.report:
        print(f"{GREEN}ok{RESET}    unsafe budgets and SAFETY comments")

    return 0 if args.report else status


if __name__ == "__main__":
    raise SystemExit(main())
