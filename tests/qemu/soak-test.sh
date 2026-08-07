#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Boots the same image many times and fails if any boot fails.
#
# Every other harness here boots once. That is enough for a fault that is
# always there, and useless for one that depends on where a timer tick lands:
# the IPC rendezvous stall fixed in M6-08 passed this project's whole suite,
# every run, for weeks, and then failed fourteen times in forty on a machine
# with real parallelism.
#
# Two things make a run count:
#
#   - **Parallelism the guest can actually use.** A CPU-oversubscribed host
#     time-slices the guest's CPUs and serialises exactly the interleavings
#     worth testing. `JOBS` defaults low for that reason -- more is not better
#     here, and 24 concurrent boots on a 40-core host hid the bug completely.
#
#     It is also how this harness lies. Four concurrent four-processor guests on
#     a host already busy will push a fourteen-second boot past any cap you
#     thought was generous, and every one of those is reported as a boot that
#     did not finish. Measured: at the old defaults this reported four failures
#     in forty, and the same image booted twenty times out of twenty, in
#     fourteen seconds each, when run one at a time. If it reports failures,
#     re-run with `JOBS=1` before believing them.
#   - **Repetition.** A one-in-three failure looks like a pass often enough to
#     be believed.
#
# Usage: soak-test.sh [runs] [jobs]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
DISK="$REPO_ROOT/build/initrd.tar"

RUNS="${1:-40}"
JOBS="${2:-2}"
# An upper bound, not the cost of a run. Each boot is stopped the moment it
# finishes, so this is only reached by a machine that never does.
TIMEOUT="${SOAK_TIMEOUT:-120}"

green=$'\e[1;32m'
red=$'\e[1;31m'
plain=$'\e[0m'
ok() { printf '%s  %s\n' "${green}ok${plain}" "$1"; }
fail() { printf '%s  %s\n' "${red}FAIL${plain}" "$1"; }

# What a finished bring-up says. One spelling, used by the waiter and by the
# tally, so a boot cannot be stopped for having finished and then counted as
# not having.
MARKER="Nothing left to do at this milestone"

[[ -f "$ISO" ]] || { fail "$ISO not found -- run 'make iso' first"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "booting $RUNS times, $JOBS at a time, ${TIMEOUT}s each..."

boot() {
    # Read-only, so concurrent boots share one image instead of fighting over
    # QEMU's exclusive write lock -- which this suite has already once reported
    # as a kernel fault.
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -M q35 -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
        -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on" \
        -device virtio-blk-pci,drive=disk0 \
        -no-reboot -cdrom "$ISO" -boot d -serial "file:$WORK/run-$1.log" \
        -display none > /dev/null 2>&1 &
    local pid=$! start
    start=$(date +%s)

    # Stopped as soon as it has finished, rather than left to run out the
    # timeout.
    #
    # This kernel does not power off -- it idles in a shell -- so a run that is
    # never stopped costs `$TIMEOUT` whether it booted in fourteen seconds or
    # hung in the first one. That made this harness slow enough not to be used,
    # and worse, made its two failure kinds indistinguishable: with the timeout
    # anywhere near the boot time, "did not finish bring-up" counted every boot
    # the host merely slowed down. Forty runs at the old default took seventeen
    # minutes and reported failures that were all clock.
    while kill -0 "$pid" 2>/dev/null; do
        if grep -q "$MARKER" "$WORK/run-$1.log" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            echo "$(( $(date +%s) - start ))" > "$WORK/time-$1"
            return 0
        fi
        sleep 0.5
    done
    return 1
}

run=0
while [[ $run -lt $RUNS ]]; do
    for _ in $(seq 1 "$JOBS"); do
        [[ $run -lt $RUNS ]] || break
        run=$((run + 1))
        boot "$run" &
    done
    wait
done

# A boot that never reached the end of the self-tests is a failure too, and a
# different one from a self-test that ran and said no -- so they are counted
# apart rather than both as "not ok".
failed=0
truncated=0
for log in "$WORK"/run-*.log; do
    if grep -q "FAILED" "$log"; then
        failed=$((failed + 1))
        [[ $failed -eq 1 ]] && {
            echo "  first failure:"
            grep -m 4 "FAILED" "$log" | sed 's/^/    /'
            grep -E "ipc            (thread|trace)" "$log" | sed 's/^/    /'
        }
    elif ! grep -q "$MARKER" "$log"; then
        truncated=$((truncated + 1))
    fi
done

passed=$((RUNS - failed - truncated))
echo
# The slowest boot, because a soak that reports only pass or fail hides the one
# number that says whether the timeout is anywhere near the truth.
slowest=0
for stamp in "$WORK"/time-*; do
    [[ -f $stamp ]] || continue
    read -r seconds < "$stamp"
    [[ $seconds -gt $slowest ]] && slowest=$seconds
done

if [[ $failed -eq 0 && $truncated -eq 0 ]]; then
    ok "$RUNS boots, no self-test failed (slowest ${slowest}s against a ${TIMEOUT}s cap)"
    exit 0
fi
[[ $failed -gt 0 ]] && fail "$failed of $RUNS boots failed a self-test"
[[ $truncated -gt 0 ]] && fail "$truncated of $RUNS boots did not finish bring-up"
echo "  ($passed passed, which is why one run proves nothing)"
exit 1
