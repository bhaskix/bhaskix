#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M1 exit criterion, as an executable check.
#
# Boots the ISO in QEMU, captures the serial console, and asserts the kernel
# reached the end of kernel_main without a fault. Used by `make test` and by CI.
#
#   tests/qemu/boot-test.sh bios
#   tests/qemu/boot-test.sh uefi
#
# Exits non-zero with the captured log on any failure.

set -uo pipefail

MODE="${1:-bios}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
LOG="$(mktemp)"
TIMEOUT="${BOOT_TEST_TIMEOUT:-40}"

trap 'rm -f "$LOG"' EXIT

# The greeting is the milestone's contract. If you reword it, update
# docs/roadmap.md M1 and kernel/src/lib.rs::banner in the same change.
EXPECT_GREETING="Hello from Bhaskix"

# Strings that mean the boot went wrong even if the greeting appeared.
FAILURE_MARKERS=("KERNEL PANIC" "FATAL:" "WARNING: the memory map was truncated"
                 "unexpected interrupt on vector" "NO TICKS")

fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }

[[ -f "$ISO" ]] || { fail "$ISO not found -- run 'make iso' first"; exit 1; }

QEMU_ARGS=(-M q35 -cpu ${QEMU_CPU:-max} -m 256M -no-reboot -cdrom "$ISO" -boot d
           -serial "file:$LOG" -display none)

if [[ "$MODE" == "uefi" ]]; then
    OVMF_CODE=""
    for candidate in /usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF.fd \
                     /usr/share/edk2/ovmf/OVMF_CODE.fd; do
        [[ -f "$candidate" ]] && { OVMF_CODE="$candidate"; break; }
    done
    if [[ -z "$OVMF_CODE" ]]; then
        # Skip rather than fail: a machine without OVMF can still validate the
        # BIOS path, and pretending otherwise would make CI red for a missing
        # package rather than a broken kernel.
        printf '\033[1;33mskip\033[0m  uefi boot test (OVMF not installed)\n'
        exit 0
    fi
    VARS="$REPO_ROOT/build/OVMF_VARS_test.fd"
    for candidate in /usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/ovmf/OVMF_VARS.fd; do
        [[ -f "$candidate" ]] && { cp "$candidate" "$VARS"; break; }
    done
    QEMU_ARGS+=(-drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE"
                -drive "if=pflash,unit=1,format=raw,file=$VARS")
fi

echo "booting ($MODE), timeout ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" >/dev/null 2>&1
# The kernel halts rather than exiting, so QEMU is always killed by the
# timeout. That is expected; what matters is what reached the serial port.

status=0

if grep -qF "$EXPECT_GREETING" "$LOG"; then
    pass "greeting present"
else
    fail "greeting '$EXPECT_GREETING' not found on serial"
    status=1
fi

for marker in "${FAILURE_MARKERS[@]}"; do
    if grep -qF "$marker" "$LOG"; then
        fail "found failure marker: $marker"
        status=1
    fi
done

# Reaching the last line proves kernel_main ran to completion rather than
# faulting somewhere in the middle -- which a greeting alone would not show.
if grep -qF "M1 complete" "$LOG"; then
    pass "kernel_main ran to completion"
else
    fail "kernel_main did not reach the end of M1"
    status=1
fi

# M2: interrupts must actually be delivered, not merely enabled. Asserting on
# observed ticks rather than on "interrupts ENABLED" is the difference between
# testing that the code ran and testing that the hardware responded.
if grep -qF "timer          delivering" "$LOG"; then
    pass "timer interrupts delivered"
else
    fail "no timer interrupts were delivered"
    status=1
fi

if grep -qF "hlt wakes on interrupt" "$LOG"; then
    pass "hlt wakes on interrupt (idle path)"
else
    fail "hlt did not wake on a timer interrupt"
    status=1
fi

# The handoff must have been validated, not skipped.
if grep -qF "handoff version 1" "$LOG"; then
    pass "handoff accepted"
else
    fail "handoff was not reported -- validation may have been skipped"
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo
    echo "--- captured serial output ---"
    cat "$LOG"
    echo "--- end ---"
fi

exit $status
