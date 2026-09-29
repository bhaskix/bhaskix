#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tally the `reading` lines every CI boot prints, passing or not.

## Why this exists

`boot-test.sh` dumps the machine's serial output only when a boot fails, so
until 2026-09-29 no per-boot counter this tree prints ever reached CI from a
*healthy* boot: of the 60 boot and shell jobs in runs 758-767, the 56 that
passed carried no serial at all. `ci-count.py` reads failed jobs, which is the
right instrument for "how often does this failure appear" and the wrong one
for "what does a healthy boot read".

Since `ec47dab`, every boot copies a few lines into its job log prefixed
`reading`. This reads them across runs and says, for each, what healthy boots
read and which boots departed from it.

## What it will not do

A boot job whose log carries **no** reading -- older than the change, or cut
short -- is counted as *blind*, never as clean. A tally that quietly drops the
boots it could not read reports a rate over the ones it could, which is the
voided-denominator mistake `coding-style.md` §8 charges for.

Needs `gh auth login`. Not a gate: it needs the network. Logs are cached in
`build/ci-logs`, shared with `ci-count.py`.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from collections import Counter
from pathlib import Path

# Importing `ci-count.py` would otherwise leave a `__pycache__` in `tools/`.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ci_count", HERE / "ci-count.py")
ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci)

# The date the `reading` lines landed. Boots before it are not blind, they
# are simply from before the question was asked, and are not fetched.
LANDED = "2026-09-29"

PATTERNS = {
    "signals": re.compile(r"hosted signals +(\d+) raised, (\d+) delivered"),
    "timed": re.compile(
        r"hosted timed +(\d+) timed wait\(s\) released early, (\d+) abandoned.*?; (\d+) nanosleep"
    ),
    "identity": re.compile(r"identity +(\d+) read\(s\) of the running thread retried.*?at most (\d+)"),
    "capabilities": re.compile(r"capabilities (\d+) live before, (\d+) after"),
}


def readings(text: str) -> dict[str, tuple[int, ...]]:
    found = {}
    for line in text.splitlines():
        if "reading " not in line:
            continue
        for name, pattern in PATTERNS.items():
            match = pattern.search(line)
            if match:
                found[name] = tuple(int(group) for group in match.groups())
    return found


def departs(name: str, values: tuple[int, ...]) -> str | None:
    """Why a reading is off the healthy baseline, or None."""
    if name == "signals" and values[0] != values[1]:
        return f"{values[0]} raised, {values[1]} delivered"
    if name == "identity" and values[0] != 0:
        return f"{values[0]} identity retr(ies), at most {values[1]} in one read"
    if name == "capabilities" and values[0] != values[1]:
        return f"capabilities {values[0]} before, {values[1]} after"
    if name == "timed" and values[2] != 0:
        return f"{values[2]} nanosleep(s) woke early with no signal pending"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", type=ci.a_date, default=ci.a_date(LANDED),
                        help=f"ignore runs before this date (default {LANDED}, when readings landed)")
    options = parser.parse_args()

    runs = ci.every_run()
    if runs is None:
        print("  \033[1;31mFAIL\033[0m  could not list runs -- is `gh auth login` done?")
        return 1
    runs = [r for r in runs if ci.when(r["created_at"]) >= options.since]

    boots = 0
    blind = []
    tally: dict[str, Counter] = {name: Counter() for name in PATTERNS}
    odd = []
    for run in sorted(runs, key=lambda r: r["run_number"]):
        jobs = ci.gh(
            f"/repos/{ci.REPO}/actions/runs/{run['id']}/jobs?per_page=100",
            jq='.jobs[] | select(.name | test("boot")) | "\\(.id) \\(.name)"',
        )
        for line in (jobs or "").splitlines():
            job, _, name = line.partition(" ")
            text = ci.job_log(job)
            found = readings(text or "")
            if not found:
                blind.append(f"{run['run_number']} {name}")
                continue
            boots += 1
            for reading, values in found.items():
                tally[reading][values] += 1
                why = departs(reading, values)
                if why:
                    odd.append(f"run {run['run_number']} {run['head_sha'][:7]} {name}: {why}")

    print(f"  readings from {boots} boot(s) in {len(runs)} run(s) since {options.since:%Y-%m-%d}; "
          f"{len(blind)} boot log(s) carried none -- blind, not clean")
    for reading, counts in tally.items():
        shown = ", ".join(f"{'/'.join(map(str, values))} x{n}" for values, n in counts.most_common())
        print(f"    {reading:<13} {shown or 'no readings'}")
    for line in odd:
        print(f"  \033[93m  off baseline  {line}\033[0m")
    if not odd and boots:
        print("  \033[1;32mok\033[0m    every boot that was read is on the healthy baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
