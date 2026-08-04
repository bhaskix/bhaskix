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
#   - **Repetition.** A one-in-three failure looks like a pass often enough to
#     be believed.
#
# Usage: soak-test.sh [runs] [jobs]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
DISK="$REPO_ROOT/build/initrd.tar"

RUNS="${1:-40}"
JOBS="${2:-4}"
TIMEOUT="${SOAK_TIMEOUT:-25}"

green=$'\e[1;32m'
red=$'\e[1;31m'
plain=$'\e[0m'
ok() { printf '%s  %s\n' "${green}ok${plain}" "$1"; }
fail() { printf '%s  %s\n' "${red}FAIL${plain}" "$1"; }

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
        -no-reboot -cdrom "$ISO" -boot d -serial stdio -display none \
        > "$WORK/run-$1.log" 2>&1
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
    elif ! grep -q "Nothing left to do at this milestone" "$log"; then
        truncated=$((truncated + 1))
    fi
done

passed=$((RUNS - failed - truncated))
echo
if [[ $failed -eq 0 && $truncated -eq 0 ]]; then
    ok "$RUNS boots, no self-test failed"
    exit 0
fi
[[ $failed -gt 0 ]] && fail "$failed of $RUNS boots failed a self-test"
[[ $truncated -gt 0 ]] && fail "$truncated of $RUNS boots did not finish bring-up"
echo "  ($passed passed, which is why one run proves nothing)"
exit 1
