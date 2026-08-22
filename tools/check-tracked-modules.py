#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every module a tracked file declares must itself be tracked.

`make test` builds the *working tree*. What gets pushed is the *index*. Those
are the same thing right up until they are not, and on 2026-08-22 they were not:
`third_party/xhci/src/lib.rs` was committed declaring `pub mod doorbell;` and
`pub mod runtime;` while neither file was ever added. Every local build passed,
because the files were sitting on disk untracked. The pushed tree did not
compile, and stayed that way across three commits and two pushes before anybody
noticed.

Nothing in the suite could have caught it. A test that builds what you have
cannot tell you what you gave away.

This is the cheap half of that check: not a full build of the archived tree,
which costs minutes, but the one class of mistake that produced it. For every
`mod x;` in a tracked Rust file, either `x.rs` or `x/mod.rs` must be tracked
beside it. Inline modules -- `mod tests { ... }` -- declare a body rather than a
file and are not the subject.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

GREEN = "\033[1;32m"
RED = "\033[1;31m"
RESET = "\033[0m"

# `mod name;` or `pub mod name;`, with optional visibility and no body. The
# trailing semicolon is what distinguishes a file module from an inline one.
DECLARATION = re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")


def tracked_files() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, text=True, check=True
    ).stdout
    return {name for name in out.split("\0") if name}


def main() -> int:
    tracked = tracked_files()
    rust = sorted(name for name in tracked if name.endswith(".rs"))
    missing: list[tuple[str, int, str]] = []

    for name in rust:
        path = Path(name)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Tracked but not present in the working tree: not this check's
            # business, and `git` will have said so already.
            continue

        # A module declared in `foo/mod.rs` or `foo/lib.rs` looks for its
        # children beside that file; one declared in `foo/bar.rs` looks in
        # `foo/bar/`. That is Rust's rule and it is what makes the two forms
        # below different.
        stem = path.stem
        directory = path.parent if stem in ("mod", "lib", "main") else path.parent / stem

        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("//"):
                continue
            found = DECLARATION.match(line)
            if not found:
                continue
            child = found.group(1)
            candidates = (directory / f"{child}.rs", directory / child / "mod.rs")
            if not any(str(c) in tracked for c in candidates):
                missing.append((name, number, child))

    if missing:
        for name, number, child in missing:
            print(f"{RED}FAIL{RESET}  {name}:{number} declares `mod {child};` and no file for it is tracked")
        print()
        print("        The working tree builds and the pushed tree does not.")
        print("        `git add` the file, or delete the declaration.")
        return 1

    print(f"  {GREEN}ok{RESET}    every declared module has a tracked file ({len(rust)} sources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
