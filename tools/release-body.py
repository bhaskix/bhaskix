#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The release note, as a GitHub release's body.

`docs/release-notes.md` links relatively -- `rfc/0091-...md`, `../TRACKER.md`,
`#running-it` -- which is right in the repository and wrong on a release page,
where every one of those resolves against the release's own URL and leads
nowhere. So each relative link is rewritten to the file at the release's tag,
and an in-page anchor to the note's own copy at that tag. The licence comment
at the top is dropped, because a release page would show it as text.

Refuses, rather than prints, a body with a relative link left in it or one
longer than a release body may be.

  tools/release-body.py TAG > body.md
"""
from __future__ import annotations

import posixpath
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/bhaskix/bhaskix"
NOTE = "docs/release-notes.md"
LINK = re.compile(r"\]\(([^)\s]+)\)")
# GitHub refuses a release body past 125,000 characters.
MOST = 125_000


def rewrite(href: str, ref: str) -> str:
    if re.match(r"[a-z]+:", href):
        return href
    if href.startswith("#"):
        return f"{REPO}/blob/{ref}/{NOTE}{href}"
    path, _, anchor = href.partition("#")
    target = posixpath.normpath(posixpath.join(posixpath.dirname(NOTE), path))
    kind = "tree" if path.endswith("/") else "blob"
    return f"{REPO}/{kind}/{ref}/{target}" + (f"#{anchor}" if anchor else "")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: tools/release-body.py TAG", file=sys.stderr)
        return 2
    ref = argv[0]
    text = (ROOT / NOTE).read_text(encoding="utf-8")
    text = re.sub(r"\A<!--.*?-->\n+", "", text, flags=re.DOTALL)
    body = LINK.sub(lambda m: f"]({rewrite(m.group(1), ref)})", text)

    left = [href for href in LINK.findall(body) if not href.startswith("https://")]
    if left:
        print(f"release-body: relative link(s) left: {', '.join(left)}", file=sys.stderr)
        return 1
    if len(body) > MOST:
        print(f"release-body: {len(body)} characters, past a release body's {MOST}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
