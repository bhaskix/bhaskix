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

A crate may additionally declare:

    unsafe_budget_exact = true

which makes the budget a **cap rather than a ceiling**: the count must equal it,
so shrinking is as much a build failure as growing until somebody edits the
number. That sounds pedantic and is not. **Headroom is permission nobody is
using**, and permission nobody is using is where the next twenty lines land
without a single reviewer being asked. A crate that opts in is one where the
number is the point -- `bin/linuxd`, whose budget went 42 to 85 in a day while
RFC 0033 was built, and which `security.md` §1 names as the largest
concentration of authority in the system.

Usage:
    tools/check-unsafe-budget.py            # check, exit non-zero on failure
    tools/check-unsafe-budget.py --report   # print the table and exit 0
"""

from __future__ import annotations

import argparse
import subprocess
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
        exact = re.search(r"^\s*unsafe_budget_exact\s*=\s*true", text, re.M) is not None
        found.append(
            (name.group(1), manifest.parent, int(budget.group(1)) if budget else None, exact)
        )
    return sorted(found)


def strip_test_modules(lines: list[str]) -> list[str]:
    """Blank out `#[cfg(test)] mod ... { ... }` blocks, keeping line numbers.

    Test code does not ship, so counting its `unsafe` against a crate's budget
    distorts the number the budget exists to track: the auditable surface of
    the kernel as deployed. Blanking rather than deleting keeps reported line
    numbers pointing at the real file.
    """
    output = list(lines)
    index = 0
    while index < len(lines):
        if lines[index].strip().startswith("#[cfg(test)]"):
            # Find the opening brace of the module that follows.
            brace = index
            while brace < len(lines) and "{" not in lines[brace]:
                brace += 1
            if brace >= len(lines):
                break
            depth = 0
            end = brace
            for end in range(brace, len(lines)):
                depth += lines[end].count("{") - lines[end].count("}")
                if depth <= 0:
                    break
            for blank in range(index, min(end + 1, len(lines))):
                output[blank] = ""
            index = end + 1
            continue
        index += 1
    return output


def _advance(depth: int, text: str) -> int:
    """Walk `text`'s braces from `depth`, stopping the moment the block closes.

    **This is the arithmetic that was wrong, and it mattered.** The scanner used
    to take `line.count("{") - line.count("}")` for the whole line, which reads
    `if let Some(x) = unsafe { f() } {` as *+1* -- two opens, one close -- and so
    believed the `unsafe` block was still open when it had already closed. Every
    line of the *outer* block was then charged to the crate's budget, sometimes
    dozens of them, none of which contains an unsafe operation.

    Once the depth returns to zero the block has ended and the rest of the line
    is ordinary code, so any brace after that point is somebody else's. Walking
    characters instead of counting them is what makes that expressible, and it
    is still a scanner anyone can read rather than a parser.
    """
    for character in text:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth <= 0:
                return 0
    return depth


def scan(source: str) -> tuple[int, list[int]]:
    """Return (lines inside unsafe blocks, line numbers missing // SAFETY:).

    Deliberately a line scanner, not a parser. A real parse would be more
    precise about string literals and macros, but the numbers only have to be
    stable and comparable between commits -- and a scanner that anyone can
    read is worth more here than one that is exactly right.
    """
    lines = strip_test_modules(source.splitlines())
    unsafe_lines = 0
    missing: list[int] = []
    depth = 0

    for index, line in enumerate(lines):
        stripped = line.strip()

        if depth > 0:
            unsafe_lines += 1
            depth = _advance(depth, line)
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
            # From the block's own opening brace, not from the start of the
            # line: anything before it -- `if let Some(x) = ` -- is not inside
            # the block and its braces are not the block's.
            opening = stripped.find("{", re.search(r"\bunsafe\s*\{", stripped).start())
            depth = _advance(0, stripped[opening:])

    return unsafe_lines, missing


# Hand-counted cases for `--self-test`. Each is (source, expected unsafe lines),
# and the expectation is a number a person worked out by reading it.
#
# **The first two are why this exists.** The scanner used to take a whole line's
# brace balance, so a line that both closed an `unsafe` block and opened another
# one read as still-open and charged the outer block's entire body to the
# budget. That over-counted `bhaskix-kernel` by 408 lines -- 19% of its declared
# number, a figure quoted in accepted RFCs and in security.md -- and nobody
# could see it, because a budget check that reports too *much* never fails a
# build. It was found only because somebody contorted a call into a `let` to
# appease it.
SELF_TEST = [
    (
        "fn f() {\n"
        "    // SAFETY: a test.\n"
        "    if let Some(x) = unsafe { g() } {\n"
        "        a();\n"
        "        b();\n"
        "    }\n"
        "}\n",
        1,
    ),
    (
        "fn f() {\n"
        "    // SAFETY: a test.\n"
        "    let y = unsafe { g() };\n"
        "    a();\n"
        "    b();\n"
        "}\n",
        1,
    ),
    (
        "fn f() {\n"
        "    // SAFETY: a test.\n"
        "    unsafe {\n"
        "        if x {\n"
        "            y();\n"
        "        }\n"
        "        z();\n"
        "    }\n"
        "    after();\n"
        "}\n",
        6,
    ),
    (
        "fn f() {\n"
        "    // SAFETY: a test.\n"
        "    unsafe { foo(|| {\n"
        "        bar()\n"
        "    }) }\n"
        "    after();\n"
        "}\n",
        3,
    ),
]


def self_test() -> int:
    """Check the scanner against hand-counted sources. Exits non-zero on any miss."""
    bad = 0
    for index, (source, expected) in enumerate(SELF_TEST):
        got, _ = scan(source)
        if got != expected:
            print(f"  {RED}FAIL{RESET}  self-test {index}: counted {got}, expected {expected}")
            bad += 1
    if bad:
        print(f"  {RED}FAIL{RESET}  the unsafe scanner miscounts {bad} of {len(SELF_TEST)} cases")
        return 1
    print(f"  {GREEN}ok{RESET}    the unsafe scanner counts {len(SELF_TEST)} hand-checked shapes correctly")
    return 0



# The crates the kernel binary links, and therefore the `unsafe` that runs in
# ring 0. Derived rather than listed: `cargo tree` answers it from the actual
# dependency graph, so a crate that starts or stops being linked moves the
# number without anybody remembering to.
#
# `docs/security.md` T9 quotes this share. It read "2,740 of them (66%) in ring
# 0" with no derivation anywhere in the tree -- computed by hand once, with an
# unstated set of crates, and stale by 2026-08-26. A figure in a security
# document that nobody can reproduce is the same defect as a claim nobody
# checks, so it is computed here now.
def kernel_linked() -> set[str] | None:
    try:
        out = subprocess.run(
            ["cargo", "tree", "-p", "bhaskix-kernel", "--target",
             "x86_64-unknown-none", "--prefix", "none", "--no-dedupe"],
            cwd=REPO, capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    linked = set()
    for line in out.stdout.splitlines():
        name = line.split(" ")[0].strip()
        if name.startswith("bhaskix"):
            linked.add(name)
    return linked or None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the table, always exit 0")
    parser.add_argument("--self-test", action="store_true", help="check the scanner itself")
    parser.add_argument(
        "--share",
        action="store_true",
        help="also print how much of the tree's unsafe is linked into the kernel",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    status = 0
    rows = []

    for name, directory, budget, exact in crates():
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
        elif exact and total < budget and not args.report:
            # The direction nobody guards, and the reason `unsafe_budget_exact`
            # exists: a crate that shrank and kept its old number is carrying
            # room for the next author to fill without asking anybody.
            print(f"{RED}FAIL{RESET}  {name}: {total} unsafe lines is under its exact budget {budget}")
            print("        This crate declares unsafe_budget_exact. Lower the number to")
            print("        match, in the same change that removed the unsafe -- headroom")
            print("        here is permission nobody is using.")
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

    if args.share:
        linked = kernel_linked()
        total = sum(count for _, count, _ in rows)
        if linked is None:
            print("  could not ask cargo which crates the kernel links")
        else:
            in_kernel = sum(count for name, count, _ in rows if name in linked)
            percent = (100 * in_kernel / total) if total else 0.0
            print(f"  {total} unsafe lines in tree, {in_kernel} of them "
                  f"({percent:.0f}%) in the kernel binary")
            print(f"  the kernel links {len(linked)} of this workspace's crates")

    if status == 0 and not args.report:
        print(f"{GREEN}ok{RESET}    unsafe budgets and SAFETY comments")

    return 0 if args.report else status


if __name__ == "__main__":
    raise SystemExit(main())
