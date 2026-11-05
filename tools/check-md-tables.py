#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A table row must not have more cells than its table has columns.

GitHub renders Markdown tables by GFM's rule: a row is split into cells at
every `|` that is not escaped as `\\|` -- **inside a code span too** -- and a
row with more cells than the header has columns keeps the first ones and
*drops the rest without a word*. So a pipe written into a command,
`` `make test | grep -c ok` ``, cuts the row there, and everything after it,
the row's status and owner included, is not on the page.

Found 2026-11-05, when a row being filed that day lost its owner cell to
`` `seq 1 200000 | head -1` ``. The scan that found it found eight more already
in the tree: TRACKER's own status table was dropping 9,548 characters of its
row about the suite, and a defect row with a table nested inside one of its
cells was dropping 30,890 -- its status among them. Nobody reads a document's
source to check what its page leaves out, so prose had no gate; this one is
it.

What it does not check: a row with *fewer* cells, which GFM pads and renders
whole; and lines after a table's blank line, which GFM renders as a paragraph
-- every pipe visible, nothing dropped, so there is nothing for this to say.
Nor the files under `tests/fixtures/`, which are wrong on purpose.

`--only FILE...` checks just those files, tracked or not. `make gates` uses it
to watch the check refuse a fixture.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPE = re.compile(r"(?<!\\)\|")
DELIMITER_CELL = re.compile(r"^\s*:?-+:?\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def cells(line: str) -> list[str]:
    """A row's cells by GFM's rule: split at unescaped pipes, the outer pair
    optional."""
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    return PIPE.split(text)


def is_delimiter(line: str) -> bool:
    if "-" not in line:
        return False
    return all(DELIMITER_CELL.match(cell) for cell in cells(line))


def check(path: Path, shown: str) -> list[str]:
    lines = path.read_text(encoding="utf-8").split("\n")
    faults = []
    fenced = False
    i = 1
    while i < len(lines):
        if FENCE.match(lines[i - 1]):
            fenced = not fenced
        header, line = lines[i - 1], lines[i]
        # GFM's own condition for a table: a header row, then a delimiter row
        # with the same number of cells.
        if (not fenced and "|" in header and is_delimiter(line)
                and len(cells(line)) == len(cells(header))):
            columns = len(cells(header))
            j = i + 1
            while j < len(lines) and lines[j].strip() and not FENCE.match(lines[j]):
                row = cells(lines[j])
                if len(row) > columns:
                    dropped = "|".join(row[columns:]).strip()
                    faults.append(
                        f"{shown}:{j + 1}: {len(row)} cells under {columns} columns -- "
                        f"GitHub drops {len(dropped)} characters, from "
                        f"{dropped[:60]!r}; escape a pipe meant as text as \\|"
                    )
                j += 1
            i = j
            continue
        i += 1
    return faults


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--only"]:
        files = [(Path(a), a) for a in args[1:]]
    else:
        listed = subprocess.run(
            ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        # Not the fixtures: they are wrong on purpose, and `--only` reads them.
        files = [(ROOT / name, name) for name in listed if not name.startswith("tests/fixtures/")]
    faults = [fault for path, shown in files for fault in check(path, shown)]
    for fault in faults:
        print(f"  \033[1;31mFAIL\033[0m  {fault}")
    if faults:
        return 1
    print(f"  \033[1;32mok\033[0m    no table row has more cells than its table has columns "
          f"({len(files)} documents)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
