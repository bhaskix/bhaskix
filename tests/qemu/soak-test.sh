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
# The second disk, and it is not optional.
#
# Without it the kernel reports "no second device on the bus; nothing
# delegated" and simply does not start the block driver in its domain, the disk
# journal, or the filesystem service -- so a soak that leaves it out is soaking
# a smaller machine than any other harness here boots, and misses exactly the
# code most likely to be timing-dependent, because it is the code with the most
# domains in it. This soak ran forty times clean while the shell test failed one
# run in twelve, and that was the whole of the difference.
DOMAIN_DISK="$REPO_ROOT/build/domain-disk.img"

# Two disks and no network, from the list every harness shares. The soak runs
# many machines at once and has nothing to say about the wire; see `devices.sh`
# for why the list is not written here.
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list disks

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
[[ -f "$DOMAIN_DISK" ]] || { fail "$DOMAIN_DISK not found -- run 'make iso' first"; exit 1; }

# Kept when something fails, because the logs are the only evidence a soak
# produces and a run that deletes them leaves "3 of 40 failed" and nothing to
# look at. Overridable so CI can put them somewhere it will upload from.
WORK="${SOAK_LOG_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
keep=0
trap '[[ $keep -eq 1 ]] || rm -rf "$WORK"' EXIT

echo "booting $RUNS times, $JOBS at a time, ${TIMEOUT}s each..."

boot() {
    # The first disk read-only, so concurrent boots share one image instead of
    # fighting over QEMU's exclusive write lock -- which this suite has already
    # once reported as a kernel fault.
    #
    # The second is *written* by the driver in its domain, so each run gets its
    # own copy. A quarter of a megabyte per concurrent run is a cheaper answer
    # than either serialising the whole soak or letting two machines write one
    # disk and reporting the result against the kernel.
    cp "$DOMAIN_DISK" "$WORK/disk-$1.img"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
        -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on" \
        -drive "file=$WORK/disk-$1.img,format=raw,if=none,id=disk1" \
        "${VIRTIO_ARGS[@]}" \
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
# The canaries, which this harness could not see until 2026-08-22.
#
# These markers are printed by a kernel that has found something deeply wrong
# and chosen to *finish anyway*, because a boot that completes its report is
# worth more than one that halts on the first sign of trouble. That choice is
# right, and it made them invisible here: none of them contains the word
# `FAILED` and every one of them appears in a boot that reaches the end
# marker, so both greps above call such a run a pass, and the logs are then
# deleted by the `EXIT` trap.
#
# Which matters because of what this harness is *for*. The 2026-08-18 fix to
# the acquire's front edge (`claim_uninterrupted`) was claimed on a mechanism
# fitting seven specimens rather than on a reproduction, and it set its own
# proof standard in writing: "the negative space -- the wedge rate of every
# suite and soak that follows, with all five markers still armed to convict a
# survivor". A soak that cannot see the markers cannot supply that proof, and
# would have quietly discarded the survivor it was run to find.
#
# The first five are that family, in the order one tear produces them. The
# rest are other families with the same habit of reporting without failing.
# **`frame check` and the fault lines are here because an instrument nobody
# greps for is not an instrument.** The interrupt-frame check added on
# 2026-08-29 records a frame the machine could not have returned through, and
# the kernel prints it on a boot that otherwise completes -- so without these
# patterns such a run counts as a pass, and `keep=0` then *deletes the log that
# held the only specimen*. That is the exact failure this harness exists to
# prevent, one level up.
#
# Two added 2026-09-02, both of which say nothing about failing and would
# therefore have been deleted with the log that held them:
#
#   - `console fatal   true` -- the console left `put_run` writing a byte at a
#     time under a per-byte lock, which is the tear closed that morning. The
#     *gate* fails on it; this harness reads the boot log and runs no gates, so
#     without a pattern here a soak boot carrying it counts as a pass.
#   - a non-zero `blocks refused` -- `mark_blocked` asked to mark a thread that
#     was not its caller. Its own comment says zero is the only correct value,
#     and it has read zero on every boot ever observed.
CANARIES='COUNT UNDERFLOW|COUNT MISMATCH|BLOCK HOLDING|SAVED HOLDING|SAVED COUNT|INVARIANT VIOLATED|LOCK ORDER|IT IS RUNNING IN SOMEBODY ELSE|frame check|FRAME CHANGED|kernel.s own bug|console fatal   true|[1-9][0-9]* blocks refused'

failed=0
truncated=0
canaries=0
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

    # Checked on every log, not as an `elif`: a boot can trip a canary and
    # still pass every self-test, and that combination is the specimen worth
    # the most -- the disease present and the machine not yet wedged by it.
    if grep -qE "$CANARIES" "$log"; then
        canaries=$((canaries + 1))
        [[ $canaries -eq 1 ]] && {
            echo "  first canary, in $(basename "$log"):"
            grep -m 8 -E "$CANARIES" "$log" | sed 's/^/    /'
        }
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

if [[ $failed -eq 0 && $truncated -eq 0 && $canaries -eq 0 ]]; then
    ok "$RUNS boots, no self-test failed and no canary tripped (slowest ${slowest}s against a ${TIMEOUT}s cap)"
    exit 0
fi
[[ $failed -gt 0 ]] && fail "$failed of $RUNS boots failed a self-test"
[[ $truncated -gt 0 ]] && fail "$truncated of $RUNS boots did not finish bring-up"
# A canary is a failure of this harness even when every boot passed, because
# the whole point of keeping the logs is to have the specimen afterwards.
[[ $canaries -gt 0 ]] && fail "$canaries of $RUNS boots tripped a canary -- a marker fired and the boot finished anyway"
echo "  ($passed passed, which is why one run proves nothing)"

# Before believing any of it, read the note at the top about oversubscription:
# on a host that cannot give each guest its processors, "did not finish
# bring-up" is the host and not the kernel.
keep=1
echo "  logs kept in $WORK"
exit 1
