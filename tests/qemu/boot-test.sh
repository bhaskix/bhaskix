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
                 "unexpected interrupt on vector" "NO TICKS"
                 "LEAK:" "INVARIANT VIOLATED")

fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }

[[ -f "$ISO" ]] || { fail "$ISO not found -- run 'make iso' first"; exit 1; }

QEMU_ARGS=(-M q35 -cpu ${QEMU_CPU:-max} -m 256M -no-reboot -cdrom "$ISO" -boot d
           -serial "file:$LOG" -display none)

if [[ "$MODE" == "uefi" ]]; then
    # OVMF ships as a CODE/VARS *pair* and they must be searched as one.
    #
    # An earlier version looked for each independently, which broke on
    # distributions that ship only the 4 MB variant: CODE was found, VARS was
    # not, and QEMU was handed `-drive file=<nonexistent>`. It exited before
    # producing a byte of output, so the failure looked like a kernel that
    # would not boot.
    #
    # The two images must also be the same size -- a 4 MB CODE with a 2 MB VARS
    # is rejected by the firmware, not by QEMU, which is a worse place to find
    # out. Hence pairs, in preference order, newest layout first.
    OVMF_CODE=""
    OVMF_VARS=""
    for pair in \
        "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
        "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
        "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd" \
        "/usr/share/qemu/OVMF_CODE.fd:/usr/share/qemu/OVMF_VARS.fd"
    do
        code="${pair%%:*}"
        vars="${pair##*:}"
        if [[ -f "$code" && -f "$vars" ]]; then
            OVMF_CODE="$code"
            OVMF_VARS="$vars"
            break
        fi
    done

    if [[ -z "$OVMF_CODE" ]]; then
        # Distinguish "not installed" from "installed but unusable". The first
        # is a fine reason to skip; the second is a broken environment and
        # skipping would hide it.
        if compgen -G "/usr/share/OVMF/*.fd" >/dev/null 2>&1 \
           || compgen -G "/usr/share/edk2/ovmf/*.fd" >/dev/null 2>&1; then
            fail "OVMF is installed but no complete CODE/VARS pair was found"
            echo "        images present:" >&2
            ls -1 /usr/share/OVMF/*.fd /usr/share/edk2/ovmf/*.fd 2>/dev/null | sed 's/^/          /' >&2
            exit 1
        fi
        printf '\033[1;33mskip\033[0m  uefi boot test (OVMF not installed)\n'
        exit 0
    fi

    echo "using firmware: $(basename "$OVMF_CODE") + $(basename "$OVMF_VARS")"

    # VARS is writable, so it must be a private copy rather than the packaged
    # image -- the firmware writes its variable store on every boot.
    mkdir -p "$REPO_ROOT/build"
    WRITABLE_VARS="$REPO_ROOT/build/OVMF_VARS_${MODE}.fd"
    cp "$OVMF_VARS" "$WRITABLE_VARS"

    QEMU_ARGS+=(-drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE"
                -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS")
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

# Reaching the last line proves the kernel ran to completion rather than
# faulting somewhere in the middle -- which a greeting alone would not show.
#
# Deliberately milestone-agnostic: an earlier version matched "M1 complete" and
# broke the moment the banner said M3, which is a test failing on its own
# wording rather than on the kernel.
if grep -qF "complete. Nothing left to do at this milestone" "$LOG"; then
    pass "kernel_main ran to completion"
else
    fail "the kernel did not run to completion"
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

# M3: the physical allocator and the heap, asserted on real memory rather than
# only in host unit tests.
if grep -qF "self test      passed, no frames leaked" "$LOG"; then
    pass "buddy allocator: no frames leaked"
else
    fail "physical allocator self test did not pass"
    status=1
fi

if grep -qF "heap           alloc works, no frames leaked" "$LOG"; then
    pass "kernel heap: Box and Vec work, no frames leaked"
else
    fail "kernel heap self test did not pass"
    status=1
fi

if grep -qF "no-execute     enabled" "$LOG"; then
    pass "no-execute enabled (W^X enforceable)"
else
    fail "no-execute is not enabled -- W^X cannot be enforced"
    status=1
fi

# The M3 exit gate from docs/memory.md §7. Negative-tested: removing the
# page-table teardown leaks 9 frames per cycle and this catches it.
if grep -qF "created and destroyed, no frames leaked" "$LOG"; then
    pass "1000 address spaces created and destroyed, no frames leaked"
else
    fail "address space frame-leak gate did not pass"
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
