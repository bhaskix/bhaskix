#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""How often a failure signature has appeared in CI, and out of how many boots.

Usage:
    tools/ci-count.py "ring stations did not retire"
    tools/ci-count.py "lock order     FAILED" --since 2026-09-01
    tools/ci-count.py "vfs            FAILED" --split 2026-09-04

# Why this exists

`TRACKER.md` records intermittent defects with a rate: *"one in roughly 1200
boots"*, *"about 6-7% of pushes"*, *"two sightings"*. Every one of those numbers
was an impression. On 2026-09-14 the ring-station row's estimate was measured
for the first time and it was **1 in 222**, five times worse than it claimed --
and the row had been carrying the wrong figure for a fortnight while people
reasoned from it about whether a fix had helped.

A rate nobody has counted is a guess wearing a number's clothes. This counts.

# The three things that make the number wrong if you skip them

**1. Annotations are not the log.** The obvious implementation asks the
annotations API: it is one request per job, it returns the `##[error]` lines,
and it agreed with both sightings that were already known. It found nine. The
answer is fourteen. A job whose harness exits non-zero without emitting per-line
error annotations carries the signature *only* in its log -- the soak run of
2026-09-06 had exactly one annotation, `Process completed with exit code 1` --
so this reads job logs, which cost about 2.5 s each and are cached below.

**2. A re-run erases the evidence from the run's own conclusion.** A job that
failed and was re-run to green leaves the run reading `success`. Two of the
fourteen are like that. So every *attempt* is walked, not just the last.

**3. A boot only counts if a failure in it would have been reported.**
`scheduling_self_test` runs at `kernel/src/lib.rs:541` and `faultinject`
triggers at `1327`, so the eight fault-injection boots in every CI run *do* run
the self-tests -- but `fault-test.sh` has no `FAILED` scan, where
`boot-test.sh` and `shell-test.sh` both do. Counting those boots in the
denominator would divide real sightings by boots that could never have produced
a visible one, and report a rate too low. They are excluded, and that means the
*incidence* is higher than the count even when the *rate* is right.

# What it cannot tell you

**Zero before a detector existed is blind, not clean.** This tool counts what
CI could see. The ring-station signature has zero sightings in the 3,681 boots
before 2026-08-26 because `d944369` added the assertion that day. Pass
`--detector-since` when the check has a birthday, and those runs are reported
separately instead of being averaged into a reassuring denominator.

**And a window chosen because it looked unusual cannot be tested against the
data that made it look unusual.** `--split` will happily compute a p-value for
the last window; it is printed with that warning attached, because the honest
use of it is prospective -- fix the boundary first, then count.

Not a gate, for `ci-status.sh`'s reason: it needs the network and `gh`.
"""

import argparse
import json
import math
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

REPO = "bhaskix/bhaskix"
CACHE = Path(__file__).resolve().parent.parent / "build" / "ci-logs"

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# What a `ci` run boots where a failure would be reported: one per `boot (...)`
# job, plus the four modes `shell-test.sh` is run in by the `interactive shell`
# job. The lane count is read per run rather than assumed -- it was four before
# `boot (iommu)` joined and is five after, and a fixed guess would misprice
# every window that straddles the change.
SHELL_MODES = 4
# `soak.yml`: SOAK_RUNS=20 boot runs plus SOAK_SHELL_RUNS=10 shell runs.
SOAK_BOOTS = 30


def gh(path, jq=None, escapes=False, paginate=False):
    """One `gh api` call, returning stdout or None if it failed."""
    cmd = ["gh", "api"]
    if escapes:
        cmd.append("--allow-escape-sequences")
    if paginate:
        cmd.append("--paginate")
    cmd.append(path)
    if jq:
        cmd += ["--jq", jq]
    done = subprocess.run(cmd, capture_output=True, text=True)
    return done.stdout if done.returncode == 0 else None


def when(stamp):
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")


def a_date(text):
    """A `--since`/`--split` argument, as a UTC midnight."""
    try:
        return datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date like 2026-09-04")


def every_run():
    """Every workflow run, newest first, paginated."""
    # **`--paginate`, and it is not optional.** Without it this returns the
    # newest hundred runs and every window below is computed against a
    # denominator that silently stops there -- which is exactly the shape of
    # mistake this tool exists to catch, and it made one on its first run.
    out = gh(
        f"/repos/{REPO}/actions/runs?per_page=100",
        jq=".workflow_runs[] | {id,run_number,conclusion,run_attempt,name,head_sha,created_at}",
        paginate=True,
    )
    if out is None:
        return None
    runs = [json.loads(line) for line in out.splitlines() if line.strip()]
    # A run still going has no conclusion and no boots to count yet.
    return [r for r in runs if r["conclusion"] is not None]


def failed_jobs(run):
    """Every failed job of every attempt -- see reason 2 in the module docs."""
    found = []
    for attempt in range(1, run["run_attempt"] + 1):
        out = gh(
            f"/repos/{REPO}/actions/runs/{run['id']}/attempts/{attempt}/jobs",
            jq='.jobs[] | select(.conclusion=="failure") | "\\(.id)\\t\\(.name)"',
        )
        for line in (out or "").splitlines():
            if "\t" in line:
                job, name = line.split("\t", 1)
                found.append((job, name, attempt))
    return found


ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def job_log(job):
    """A job's log, from the cache if it is there. Logs never change."""
    CACHE.mkdir(parents=True, exist_ok=True)
    kept = CACHE / f"{job}.log"
    if kept.exists():
        return kept.read_text(encoding="utf-8", errors="replace")
    out = gh(f"/repos/{REPO}/actions/jobs/{job}/logs", escapes=True)
    if out is None:
        # GitHub drops logs after its retention window. Recorded as unreadable
        # rather than counted as clean: see "Zero ... is blind, not clean".
        return None
    text = ESCAPE.sub("", out)
    kept.write_text(text, encoding="utf-8")
    return text


def boots_in(run, lanes):
    """Boots in this run whose failure would have been reported."""
    if run["name"] == "soak":
        return SOAK_BOOTS
    return lanes.get(run["run_number"], 0)


def lane_count(run):
    """`boot (...)` jobs plus the shell job's modes, read from the run itself."""
    out = gh(f"/repos/{REPO}/actions/runs/{run['id']}/jobs?per_page=100", jq=".jobs[].name")
    names = (out or "").splitlines()
    lanes = sum(1 for n in names if n.startswith("boot ("))
    shells = sum(1 for n in names if n.startswith("interactive shell"))
    return lanes + SHELL_MODES * shells


def at_least_two(hits, boots, rate):
    """P(this many or more), at `rate`. Poisson, which is the right shape for
    a rare independent event and does not need a boot-by-boot model."""
    if boots == 0 or rate <= 0:
        return None
    mean = rate * boots
    below = sum(math.exp(-mean) * mean**k / math.factorial(k) for k in range(hits))
    return max(0.0, min(1.0, 1.0 - below))


def main():
    ap = argparse.ArgumentParser(
        description="Count a failure signature across CI history.",
        epilog="Needs `gh auth login`. Not a gate: it needs the network.",
    )
    ap.add_argument("signature", help="the exact text to look for in job logs")
    ap.add_argument("--since", type=a_date, help="ignore runs before this date")
    ap.add_argument(
        "--split",
        type=a_date,
        action="append",
        default=[],
        help="cut the history here; may be given more than once",
    )
    ap.add_argument(
        "--detector-since",
        type=a_date,
        help="the date the check that reports this signature landed: before it, "
        "a zero means nobody was looking",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        print(f"{RED}ci-count{RESET}: `gh auth login` first -- job logs need a token.", file=sys.stderr)
        return 2

    runs = every_run()
    if runs is None:
        print(f"{RED}ci-count{RESET}: could not list runs.", file=sys.stderr)
        return 2
    if args.since:
        runs = [r for r in runs if when(r["created_at"]) >= args.since]
    runs.sort(key=lambda r: r["created_at"])
    if not runs:
        print("no runs in that range.")
        return 0

    print(
        f"{DIM}{len(runs)} runs, {runs[0]['created_at'][:10]} to "
        f"{runs[-1]['created_at'][:10]}. Reading job logs (cached in "
        f"{CACHE.relative_to(CACHE.parent.parent)}/)...{RESET}",
        file=sys.stderr,
    )

    hits, unreadable = set(), 0
    lanes = {}
    for i, run in enumerate(runs, 1):
        if i % 25 == 0:
            print(f"{DIM}  ... {i}/{len(runs)}{RESET}", file=sys.stderr)
        if run["name"] != "soak":
            lanes[run["run_number"]] = lane_count(run)
        if run["conclusion"] != "failure" and run["run_attempt"] == 1:
            continue  # nothing failed in it, so nothing to read
        for job, name, attempt in failed_jobs(run):
            text = job_log(job)
            if text is None:
                unreadable += 1
                continue
            if args.signature in text:
                hits.add((run["name"], run["run_number"], name, run["created_at"]))

    edges = [when(runs[0]["created_at"]) - timedelta(seconds=1)]
    if args.detector_since:
        edges.append(args.detector_since)
    edges += sorted(args.split)
    edges.append(when(runs[-1]["created_at"]) + timedelta(seconds=1))

    windows = []
    for lower, upper in zip(edges, edges[1:]):
        if lower >= upper:
            continue
        inside = [r for r in runs if lower <= when(r["created_at"]) < upper]
        boots = sum(boots_in(r, lanes) for r in inside)
        found = sum(1 for r in inside if (r["name"], r["run_number"]) in {(h[0], h[1]) for h in hits})
        blind = bool(args.detector_since and upper <= args.detector_since)
        windows.append((lower, upper, len(inside), boots, found, blind))

    if args.json:
        print(
            json.dumps(
                {
                    "signature": args.signature,
                    "sightings": sorted([list(h) for h in hits], key=lambda h: h[3]),
                    "windows": [
                        {
                            "from": w[0].strftime("%Y-%m-%d"),
                            "to": w[1].strftime("%Y-%m-%d"),
                            "runs": w[2],
                            "boots": w[3],
                            "hits": w[4],
                            "blind": w[5],
                        }
                        for w in windows
                    ],
                    "unreadable_jobs": unreadable,
                },
                indent=2,
            )
        )
        return 0

    print()
    print(f"  {BOLD}{args.signature}{RESET}")
    print()
    for name, number, job, stamp in sorted(hits, key=lambda h: h[3]):
        print(f"    {stamp[:10]}  {name:5s} run {number:<5d} {job}")
    if not hits:
        print(f"    {DIM}no sighting in any job log read{RESET}")
    print()
    print(f"  {'window':32s} {'runs':>6} {'boots':>7} {'seen':>5}  rate")
    total_hits = total_boots = 0
    for lower, upper, runs_in, boots, found, blind in windows:
        last_window = upper == edges[-1]
        span = (
            f"{lower.strftime('%d %b')} -> now"
            if last_window
            else f"{lower.strftime('%d %b')} -> {upper.strftime('%d %b')}"
        )
        if blind:
            rate = f"{YELLOW}blind: no detector yet{RESET}"
        elif found:
            rate = f"1 in {boots // found}"
            total_hits += found
            total_boots += boots
        else:
            rate = f"{GREEN}none in {boots}{RESET}"
            total_boots += boots
        print(f"  {span:32s} {runs_in:6d} {boots:7d} {found:5d}  {rate}")
    if total_hits:
        print(f"  {BOLD}{'measured':32s} {'':6s} {total_boots:7d} {total_hits:5d}  "
              f"1 in {total_boots // total_hits}{RESET}")

    # The last window against everything before it, with its own warning.
    counted = [w for w in windows if not w[5]]
    if len(counted) > 1 and total_hits:
        last = counted[-1]
        before_hits = total_hits - last[4]
        before_boots = total_boots - last[3]
        if before_hits and last[4]:
            background = before_hits / before_boots
            p = at_least_two(last[4], last[3], background)
            print()
            print(
                f"  the last window is {last[4]} in {last[3]} boots against a background of "
                f"{before_hits} in {before_boots} (1 in {before_boots // before_hits});"
            )
            print(f"  {BOLD}P(that many or more at the background rate) = {p:.3f}{RESET}")
            print(
                f"  {YELLOW}A window chosen because it looked unusual cannot be tested against\n"
                f"  the data that made it look unusual. Fix the boundary, then count forward.{RESET}"
            )

    if unreadable:
        print()
        print(f"  {YELLOW}{unreadable} job log(s) could not be read{RESET} -- GitHub drops them "
              f"after its retention window. Those jobs are not counted either way.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
