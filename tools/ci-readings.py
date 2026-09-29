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
import json
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

# The first CI run carrying the killer probe's handshake (`3809af4`). Before
# it the probe never parked its `nanosleep` child, so a boot with no early
# release is history there, not a departure -- and flagging it buried the one
# reading that mattered under fifteen that did not.
HANDSHAKE_RUN = 771

PATTERNS = {
    "signals": re.compile(r"hosted signals +(\d+) raised, (\d+) delivered"),
    "timed": re.compile(
        r"hosted timed +(\d+) timed wait\(s\) released early, (\d+) abandoned.*?; (\d+) nanosleep"
    ),
    "identity": re.compile(r"identity +(\d+) read\(s\) of the running thread retried.*?at most (\d+)"),
    "capabilities": re.compile(r"capabilities (\d+) live before, (\d+) after"),
    # For the TCP step-4 row: rendezvous dropped after matching and wakes that
    # reached a partner not yet blocked; tcpd's calls dequeued, RECVs, answers.
    "handover": re.compile(r"ipc handover\* +(\d+) rendezvous dropped after matching, (\d+) wake"),
    "tcpd": re.compile(r"tcpd served\* +(\d+) call\(s\) dequeued, (\d+) of them RECV, (\d+) answer"),
    # Signal deliveries on the first ask, and on a retry after a park and a
    # wake -- the second is the path the killer probe's children are for.
    "deliver": re.compile(r"hosted deliver +(\d+) delivered as the call was made, (\d+) to a call"),
    # Hosted calls the nucleus answered itself: retries exhausted, and parked
    # calls ended because their thread was told to stop -- which the killer
    # probe's SIGKILL child and the sibling it ends each contribute one of.
    "park": re.compile(r"linux park +the nucleus answered \d+ hosted call\(s\) itself: (\d+) RAN OUT OF RETRIES, (\d+) whose"),
    # Parks the nucleus refused, and how many because the notification already
    # had a waiter -- the signature of a wake slot handed to two parkers at
    # once (the pipe and wait4 defects of 2026-09-29). Printed only when
    # non-zero, so every boot that carries it is off baseline.
    "refused": re.compile(r"linux park +(\d+) parks refused: .*?(\d+) by the notification itself"),
    # Deadline arms refused for want of a slot, and the most slots ever armed
    # at once -- for the TCP step-4 row, whose client was parked on a wake
    # that `news` had tried to give a 100 ms deadline.
    "slots": re.compile(r"deadline slots +(\d+) arm\(s\) refused for want of a slot, at most (\d+) of"),
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


def departs(name: str, values: tuple[int, ...], run: int) -> str | None:
    """Why a reading is off the healthy baseline, or None."""
    if name == "signals" and values[0] != values[1]:
        return f"{values[0]} raised, {values[1]} delivered"
    if name == "identity" and values[0] != 0:
        return f"{values[0]} identity retr(ies), at most {values[1]} in one read"
    if name == "refused" and values[0] != 0:
        return f"{values[0]} park(s) refused, {values[1]} by a notification that already had a waiter"
    if name == "slots" and values[0] != 0:
        return f"{values[0]} deadline arm(s) refused for want of a slot (at most {values[1]} armed)"
    if name == "handover" and values[0] != 0:
        return f"{values[0]} rendezvous dropped after matching"
    if name == "tcpd" and values[0] != values[2]:
        return f"tcpd dequeued {values[0]} call(s) and answered {values[2]}"
    if name == "capabilities" and values[0] != values[1]:
        return f"capabilities {values[0]} before, {values[1]} after"
    if name == "timed" and values[2] != 0:
        return f"{values[2]} nanosleep(s) woke early with no signal pending"
    # Since the killer probe's handshake (2026-09-29) its `nanosleep` child is
    # asleep when signalled, so a healthy boot releases at least one timed wait
    # early. Zero means the parked-sleep delivery was not exercised on that
    # boot -- which was every boot before the handshake.
    # The `hosted deliver` line landed with the pipe child's handshake, so any
    # boot that prints it has both children waiting to be signalled asleep:
    # fewer than two deliveries to a woken call means one of them was not.
    if name == "deliver" and values[1] < 2:
        return f"only {values[1]} delivery(ies) met a woken call: a probe child was signalled before it parked"
    if name == "timed" and values[0] == 0 and run >= HANDSHAKE_RUN:
        return "no timed wait was released early: the parked-sleep delivery was not exercised"
    return None


def runs_since(since) -> list | None:
    """Finished runs created on or after `since`, asked for by date.

    **Not `ci-count.py`'s `every_run`, which pages through the whole history**
    -- deliberately, since its denominator is every boot there has been. This
    tool only ever reads runs since the readings landed, and paging through
    eight hundred runs to keep fifteen cost the account its hourly API budget
    on 2026-09-29. `created=>=` narrows the listing on GitHub's side; still
    paginated, so a busy day is not cut off at a hundred.
    """
    out = ci.gh(
        f"/repos/{ci.REPO}/actions/runs?per_page=100&created=>={since:%Y-%m-%d}",
        jq=".workflow_runs[] | {id,run_number,conclusion,run_attempt,name,head_sha,created_at}",
        paginate=True,
    )
    if out is None:
        return None
    runs = [json.loads(line) for line in out.splitlines() if line.strip()]
    return [r for r in runs if r["conclusion"] is not None]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", type=ci.a_date, default=ci.a_date(LANDED),
                        help=f"ignore runs before this date (default {LANDED}, when readings landed)")
    options = parser.parse_args()

    runs = runs_since(options.since)
    if runs is None:
        print("  \033[1;31mFAIL\033[0m  could not list runs -- is `gh auth login` done?")
        return 1

    boots = 0
    blind = []
    tally: dict[str, Counter] = {name: Counter() for name in PATTERNS}
    odd = []
    for run in sorted(runs, key=lambda r: r["run_number"]):
        jobs = ci.gh(
            f"/repos/{ci.REPO}/actions/runs/{run['id']}/jobs?per_page=100",
            # The soak's "repeated boots and shell runs" job is not a boot
            # lane: each of its boots keeps its serial as an artifact
            # (`soak-logs`), never in the job log, so it carries no reading
            # here and would be counted blind every time. Reading those
            # artifacts is a larger source this tool does not reach yet.
            jq='.jobs[] | select(.name | test("boot")) | select(.name | test("repeated") | not) | "\\(.id) \\(.name)"',
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
                why = departs(reading, values, run["run_number"])
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
