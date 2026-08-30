#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Documents must not claim a toolchain version the tree stopped using.

On 2026-08-22 `rust-toolchain.toml` was pinned to 1.98.0. Eight days later
`README.md`, `docs/nightly-features.md` and `docs/release-notes.md` still said
1.97.1 -- the last of those written *that morning*, which inherited the claim by
copying it from the first rather than checking it.

Nothing in the suite could have caught that. Every gate here asks whether the
code does what it says; none asked whether the documents describe the thing that
was built. A release note is read by people who cannot check it, which is
exactly why it is the worst place for a number nobody verified.

**What it polices, and why not everything.** Tracked Markdown, excluding
`TRACKER.md` and `docs/rfc/`: both are historical records, and an RFC that says
what the toolchain was when it was written is correct precisely by not being
updated. Everything else is describing the tree as it stands now.

**Three components, not two.** `Rust 1.98.0` is a claim about what this builds
with; `Rust 1.97` is usually prose about when something changed -- as in
`arch/x86_64/src/context.rs`, which records the release a lint began rejecting
something and is still true. Requiring the patch level keeps the check on
claims and off history.

Whitespace is collapsed before matching, because these documents are wrapped and
`Verified with Rust\n1.98.0` is one claim across two lines.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_FILES = {"TRACKER.md"}
EXCLUDED_DIRS = ("docs/rfc/",)
CLAIM = re.compile(r"Rust (\d+\.\d+\.\d+)")


def pinned_channel() -> str:
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r'channel\s*=\s*"([^"]+)"', text)
    if match is None:
        sys.exit("check-doc-versions: rust-toolchain.toml declares no channel")
    return match.group(1)


def tracked_markdown() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        path
        for path in out.stdout.split()
        if path not in EXCLUDED_FILES
        and not any(path.startswith(prefix) for prefix in EXCLUDED_DIRS)
    ]


def main() -> int:
    want = pinned_channel()
    wrong: list[tuple[str, str]] = []
    checked = 0

    for path in tracked_markdown():
        text = (ROOT / path).read_text(encoding="utf-8", errors="replace")
        for found in CLAIM.findall(" ".join(text.split())):
            checked += 1
            if found != want:
                wrong.append((path, found))

    if wrong:
        print(f"FAILED  rust-toolchain.toml pins {want}, but:", file=sys.stderr)
        for path, found in wrong:
            print(f"          {path} claims Rust {found}", file=sys.stderr)
        print(
            "        A number copied is a number unverified. Update the "
            "document, or the pin.",
            file=sys.stderr,
        )
        return 1

    print(f"ok    {checked} toolchain claim(s) in the documents match {want}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
