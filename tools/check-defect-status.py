#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A defect row's status cell must not contradict its own body.

TRACKER's defect table carries the status twice: once in the status cell, and
again in the body, where a row records how it was closed and by what. Those two
drift apart, and when they do the row is worse than useless -- a reader who
trusts the cell hunts a defect that is fixed, and one who trusts the body stops
hunting a defect that is live.

Both directions were real on 2026-09-05. Two of the five rows whose cell read
`OPEN` had bodies announcing their own closure:

  * the hosted staging write, cell `OPEN`, body "FIXED 2026-09-04" with a
    six-boot before/after table
  * the 40,960-byte file limit, cell `OPEN`, body "CLOSED 2026-09-01 by
    RFC 0065", with the RFC accepted and the code in the tree

Neither was a typo; both were rows updated in the body by whoever fixed them,
with the cell left alone. Prose has no gate. This one does.
"""

import re
import sys
from pathlib import Path

TRACKER = Path(__file__).resolve().parent.parent / "TRACKER.md"

# A row's own closure announcement. Deliberately narrow: a bare "closed" in a
# sentence is prose, but "CLOSED 2026-09-01" or "**FIXED 2026-09-04**" is a row
# stating its own outcome, which is what contradicts the cell.
SETTLED = re.compile(r"\*\*(?:CLOSED|FIXED|RESOLVED|ROOT-CAUSED)\b|(?:CLOSED|FIXED|RESOLVED) 20\d\d-\d\d-\d\d")
OPEN_CELL = re.compile(r"\|\s*🔍\s*`OPEN`\s*\|")


def rows(text):
    """Table rows, joined across the physical lines a row is wrapped over."""
    out, current, start = [], None, 0
    for number, line in enumerate(text.split("\n"), 1):
        if line.startswith("| **"):
            if current is not None:
                out.append((start, "\n".join(current)))
            current, start = [line], number
        elif current is not None:
            current.append(line)
    if current is not None:
        out.append((start, "\n".join(current)))
    return out


def main():
    text = TRACKER.read_text(encoding="utf-8")
    bad = []
    checked = 0
    for line, row in rows(text):
        cell = OPEN_CELL.search(row)
        if not cell:
            continue
        checked += 1
        # Only the body -- the text after the status cell -- can contradict it.
        body = row[cell.end():]
        found = SETTLED.search(body)
        if found:
            title = row[4:].split("**")[0][:72]
            bad.append((line, title, found.group(0)))

    if not bad:
        print(f"  \033[1;32mok\033[0m    every OPEN defect row agrees with its body ({checked} checked)")
        return 0

    for line, title, marker in bad:
        print(
            f"  \033[1;31mFAIL\033[0m  TRACKER.md:{line} says `OPEN` but its body says "
            f"{marker!r}\n        {title}",
            file=sys.stderr,
        )
    print(
        "        Update the status cell, or say in the body why the row is still open.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
