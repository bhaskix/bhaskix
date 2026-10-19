#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A document must not tell a reader to type what the shell does not have.

On 2026-10-19 the release ISO was booted the way a stranger would boot it, and
the first commands the README and `make demo` suggest were typed at it. One of
them, `ps`, answered `ps: not a command. Try 'help'.` -- the user-mode shell has
never had it; only the kernel's operator shell does. Both documents had said it
since they were written, and nothing could have caught it: every gate asked
whether the shell does what it says, and none asked whether the documents name
a shell that exists.

So this reads the commands from the shells themselves -- the arms of each
dispatch `match` -- and checks every command a document puts after a prompt:

  * `bhaskix$ <command>` against the user-mode shell, `user/shell/src/main.rs`,
    and `bhaskix$ pkg <verb>` against `pkg`'s own arms;
  * `bhaskix> <command>` against the kernel shell, `kernel/src/shell.rs`;
  * the suggestions in `tools/demo.sh`'s banner, which a reader is told to type
    at the `bhaskix$` prompt.

The documents are the guides under `docs/guide/`, the README, and the demo's
banner. For the guides it also checks that every relative link resolves, and
that every guide but the index says when it was last verified and against
what: a line `**Verified** <YYYY-MM-DD> against <commit or tag>`. A guide is a
transcript of something that was run, and a transcript without a date is a
claim nobody can re-check.

`--only FILE...` checks just those files, as guides, whether git tracks them or
not. `make gates` uses it to watch the check refuse a fixture.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USER_SHELL = "user/shell/src/main.rs"
KERNEL_SHELL = "kernel/src/shell.rs"
DEMO = "tools/demo.sh"
README = "README.md"
GUIDES = "docs/guide/"
INDEX = "docs/guide/README.md"

# `[ \t]`, never `\s`, after a prompt: `\s` crosses a newline, so one prompt line
# swallowed the next and the check counted ten of the README's and the demo's
# eleven commands on the day it was written. The fixture puts two prompt lines
# back to back so that cannot come back unseen.
ARM = re.compile(r'^\s*b"([a-z0-9-]+)"\s*(?:if [^\n]*?)?=>', re.MULTILINE)
USER_PROMPT = re.compile(r"^[ \t]*bhaskix\$ (\S+)(?:[ \t]+(\S+))?", re.MULTILINE)
KERNEL_PROMPT = re.compile(r"^[ \t]*bhaskix> (\S+)", re.MULTILINE)
DEMO_SUGGESTION = re.compile(r"^[ \t]*\$\{cyan\}([a-z0-9-]+)", re.MULTILINE)
LINK = re.compile(r"\]\(([^)\s]+)\)")
VERIFIED = re.compile(r"^\*\*Verified\*\* \d{4}-\d{2}-\d{2} against \S+", re.MULTILINE)


def arms(path: str, opening: str) -> set[str]:
    """The byte-string arms of the `match` that follows `opening` in `path`."""
    text = (ROOT / path).read_text(encoding="utf-8")
    start = text.find(opening)
    if start < 0:
        sys.exit(f"check-guides: {path} no longer contains {opening!r}")
    body = text[start:]
    end = body.find("\n}\n")
    found = set(ARM.findall(body[: end if end > 0 else len(body)]))
    if not found:
        sys.exit(f"check-guides: no commands found after {opening!r} in {path}")
    return found


def tracked_guides() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", f"{GUIDES}*.md"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split()


def check_commands(path: str, text: str, user: set[str], pkg: set[str],
                   kernel: set[str]) -> list[str]:
    problems = []
    for command, verb in USER_PROMPT.findall(text):
        if command not in user:
            problems.append(f"{path}: `bhaskix$ {command}` -- the user-mode shell has no '{command}'")
        elif command == "pkg" and verb and verb not in pkg:
            problems.append(f"{path}: `bhaskix$ pkg {verb}` -- pkg has no '{verb}'")
    for command in KERNEL_PROMPT.findall(text):
        if command not in kernel:
            problems.append(f"{path}: `bhaskix> {command}` -- the kernel shell has no '{command}'")
    return problems


def check_guide(path: str, text: str) -> list[str]:
    problems = []
    base = (ROOT / path).parent
    for target in LINK.findall(text):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        if not (base / target.split("#", 1)[0]).exists():
            problems.append(f"{path}: the link '{target}' leads nowhere")
    if path != INDEX and not VERIFIED.search(text):
        problems.append(f"{path}: no '**Verified** <date> against <commit>' line")
    return problems


def main(argv: list[str]) -> int:
    user = arms(USER_SHELL, "fn run(line: &[u8])")
    pkg = arms(USER_SHELL, "fn pkg(")
    kernel = arms(KERNEL_SHELL, "match tokens[0] {")

    if argv[:1] == ["--only"]:
        guides, others = argv[1:], []
    else:
        guides, others = tracked_guides(), [README]

    problems: list[str] = []
    commands = 0
    for path in guides + others:
        text = (ROOT / path).read_text(encoding="utf-8", errors="replace")
        commands += len(USER_PROMPT.findall(text)) + len(KERNEL_PROMPT.findall(text))
        problems += check_commands(path, text, user, pkg, kernel)
        if path in guides:
            problems += check_guide(path, text)
    if argv[:1] != ["--only"]:
        demo = (ROOT / DEMO).read_text(encoding="utf-8")
        for command in DEMO_SUGGESTION.findall(demo):
            commands += 1
            if command not in user:
                problems.append(f"{DEMO}: the banner suggests '{command}', which the user-mode shell does not have")

    if problems:
        print("FAILED  a document names a shell that does not exist:", file=sys.stderr)
        for problem in problems:
            print(f"          {problem}", file=sys.stderr)
        print(
            "        Run it before writing it down. Fix the document, or the shell.",
            file=sys.stderr,
        )
        return 1

    print(
        f"ok    {commands} shell command(s) in {len(guides)} guide(s), the README and the demo"
        f" name commands the shells have"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
