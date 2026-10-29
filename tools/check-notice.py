#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every script that fetches something from outside says what, and NOTICE names it.

NOTICE listed Limine alone until 2026-10-29, while the release ISO had carried
Go's runtime since RFC 0059's Go server went in, and BusyBox had been fetched
and pinned for the test images since 2026-10-29's CI run 874. Nothing asked:
a new fetch script is a new component, and the place that says so was prose
nobody re-read.

So a tracked script under `tools/` that fetches -- `curl`, `wget` or
`git clone` -- must carry one line

    # NOTICE: <component>

naming the heading NOTICE gives that component, which NOTICE must then have
(two spaces in, at a line's start), or

    # NOTICE: none -- <why it fetches no component>

for a script that downloads but takes nothing in, such as one that reads CI
results. A script with no such line, a `none` without its reason, or a name
NOTICE lacks, is refused.

`--self-test` builds throwaway repositories, one per kind of refusal, and one
that must pass.
"""

# NOTICE: none -- names curl, wget and git clone in its own tests, and fetches nothing

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

GREEN = "\033[1;32m"
RED = "\033[1;31m"
RESET = "\033[0m"

FETCHES = re.compile(r"(?m)^[^#\n]*\b(?:curl|wget|git clone)\b")
DECLARATION = re.compile(r"(?m)^# NOTICE: (.+)$")
NONE = re.compile(r"^none -- \S")


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "tools/"], capture_output=True, check=True
    ).stdout
    return [n.decode() for n in out.split(b"\0") if n]


def refusals(root: Path) -> tuple[list[str], int]:
    notice_path = root / "NOTICE"
    notice = notice_path.read_text(encoding="utf-8") if notice_path.exists() else ""
    found, checked = [], 0
    for name in tracked(root):
        if not (name.endswith(".sh") or name.endswith(".py")):
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not FETCHES.search(text):
            continue
        checked += 1
        declared = DECLARATION.findall(text)
        if len(declared) != 1:
            found.append(f"{name}: fetches, and has {len(declared)} '# NOTICE:' lines where one is owed")
            continue
        component = declared[0].strip()
        if component.startswith("none"):
            if not NONE.match(component):
                found.append(f"{name}: '# NOTICE: none' without its reason ('none -- why')")
            continue
        if not re.search(r"(?m)^  " + re.escape(component) + r"(?:\s|$)", notice):
            found.append(f"{name}: declares '{component}', which NOTICE does not name")
    return found, checked


def self_test() -> int:
    notice = "Third-party components\n\n  Widget  (tools/fetch-widget.sh)\n    MIT.\n"
    cases = {
        "a fetching script with no declaration": ("curl -O https://x/widget\n", True),
        "a declared component NOTICE lacks": ("# NOTICE: Gadget\ncurl -O https://x/g\n", True),
        "a 'none' without its reason": ("# NOTICE: none\nwget https://x/status\n", True),
        "a declared component NOTICE names": ("# NOTICE: Widget\ncurl -O https://x/widget\n", False),
        "a 'none' with its reason": ("# NOTICE: none -- reads a status page\ncurl -s https://x/s\n", False),
    }
    failed = 0
    for label, (script, refused) in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "NOTICE").write_text(notice, encoding="utf-8")
            (root / "tools").mkdir()
            (root / "tools/fetch-widget.sh").write_text("#!/bin/sh\n" + script, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            got = bool(refusals(root)[0])
            verb = "refuses" if refused else "accepts"
            if got == refused:
                print(f"  {GREEN}ok{RESET}    the NOTICE gate {verb} {label}")
            else:
                print(f"  {RED}FAIL{RESET}  the NOTICE gate should have {'refused' if refused else 'accepted'} {label}")
                failed += 1
    return 1 if failed else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:]:
        print("usage: check-notice.py [--self-test]", file=sys.stderr)
        return 2
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    found, checked = refusals(root)
    if found:
        for line in found:
            print(f"  {RED}FAIL{RESET}  {line}")
        return 1
    print(f"  {GREEN}ok{RESET}    {checked} fetching script(s) each name their component, and NOTICE names it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
