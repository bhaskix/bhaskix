#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the interactive shell test many times and fails if any run fails.
#
# The boot soak beside this one answers "does it come up", repeatedly. This one
# answers "does it *answer*", repeatedly, and they are not the same question:
# the bug that prompted it was in neither the boot nor the shell but between
# them. The kernel's last two lines of boot output raced the shell's first, and
# tore it in half:
#
#     a user-mode s    address spaces 6 in use at once, each program in its own
#       console out    every byte reached the wire
#     hell. 'help' lists what it can do.
#     bhaskix$
#
# The shell is alive and prompting. The harness is waiting for `a user-mode
# shell` as one string, it arrived in two pieces, and so the run sits until its
# timeout and reports every check as missing. That happened for three
# milestones and was written off as a loaded host every single time -- which is
# exactly what it looks like from outside, because a slower machine interleaves
# differently and raising the timeout really does make it go away.
#
# One run cannot tell those apart. Ten can.
#
# ## Sequential, and not by oversight
#
# Unlike the boot soak, this cannot run concurrently. The shell test writes to
# `build/domain-disk.img` -- it is the disk a service drives, and the `disk`
# mode rebuilds the image outright. Two runs at once would be two machines
# writing one disk, and the failure would be reported against the kernel.
#
# Usage: soak-shell.sh [runs] [mode]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

RUNS="${1:-10}"
MODE="${2:-user}"

green=$'\e[1;32m'
red=$'\e[1;31m'
dim=$'\e[2m'
plain=$'\e[0m'
ok() { printf '%s  %s\n' "${green}ok${plain}" "$1"; }
fail() { printf '%s  %s\n' "${red}FAIL${plain}" "$1"; }

[[ -f "$REPO_ROOT/build/bhaskix.iso" ]] || {
    fail "build/bhaskix.iso not found -- run 'make iso' first"
    exit 1
}

# Kept when something fails, for the same reason the boot soak keeps its own: a
# run that reports "2 of 10 failed" and deletes the evidence has told you the
# rate and nothing about the cause.
WORK="${SOAK_LOG_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
keep=0
trap '[[ $keep -eq 1 ]] || rm -rf "$WORK"' EXIT

echo "typing at the $MODE shell $RUNS times, one at a time..."

failed=0
slowest=0
for run in $(seq 1 "$RUNS"); do
    start=$(date +%s)
    if BHASKIX_SHELL_LOG="$WORK/run-$run.log" \
        "$REPO_ROOT/tests/qemu/shell-test.sh" "$MODE" > "$WORK/out-$run.txt" 2>&1
    then
        rm -f "$WORK/run-$run.log" "$WORK/out-$run.txt"
        printf '.'
    else
        failed=$((failed + 1))
        printf '%sX%s' "$red" "$plain"
        [[ $failed -eq 1 ]] && {
            echo
            echo "  first failure, run $run:"
            grep -m 3 "FAIL" "$WORK/out-$run.txt" | sed 's/^/    /'
        }
    fi
    seconds=$(( $(date +%s) - start ))
    [[ $seconds -gt $slowest ]] && slowest=$seconds
done
echo

# The slowest run, because it is the number that says whether a failure was the
# machine or the clock. A good run of this test finishes in about twenty
# seconds; one that took the whole timeout did not fail a check, it ran out of
# time, and those are different findings with different fixes.
if [[ $failed -eq 0 ]]; then
    ok "$RUNS runs of the $MODE shell, none failed (slowest ${slowest}s)"
    exit 0
fi

fail "$failed of $RUNS runs of the $MODE shell failed"
echo "  ${dim}(slowest ${slowest}s -- a run near the harness timeout ran out of"
echo "   time rather than failing a check; one that failed fast did not)${plain}"
keep=1
echo "  logs kept in $WORK"
exit 1
