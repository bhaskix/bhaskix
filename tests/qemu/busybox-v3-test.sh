#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0094 step 5: Ubuntu's x86-64-v3 BusyBox runs -- where AVX is on.
#
# CI run 874 met this binary by accident: the runner's `/bin/busybox` became
# the `amd64v3` build, it trapped at its first `vmovdqa` because the kernel
# never enabled AVX state, and every boot lane went red. The corpus was pinned
# to the plain build that day. Since RFC 0094 step 4 the kernel enables AVX
# where the CPU offers it, so the same binary should run -- and this lane boots
# an image carrying it to say whether it does.
#
# **It judges only where AVX is on.** The boot's own `xstate` line says what
# the plan enabled. Where it enabled no AVX -- `qemu64`, or this host's QEMU
# 4.2.1, whose TCG offers no AVX and yet runs the v3 binary to completion
# without checking -- a pass would prove nothing and a failure would be the
# CPU's, not the kernel's, so the lane says it skipped and why. CI's QEMU 10.2.1
# `max` and KVM are where it means something.
#
#   tests/qemu/busybox-v3-test.sh [bios|uefi]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-bios}"
cd "$REPO_ROOT" || exit 1

pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*"; }
skip() { printf '\033[1;33mskip\033[0m  %s\n' "$*"; }

V3="$(BUSYBOX_VARIANT=amd64v3 tools/fetch-busybox.sh)" || {
    fail "could not fetch the pinned x86-64-v3 BusyBox (tools/fetch-busybox.sh)"
    exit 1
}
echo "building an image carrying the x86-64-v3 BusyBox..."
if ! make iso BUSYBOX_SRC="$V3" BUSYBOX="build/busybox-v3" \
    INITRD="build/initrd-v3.tar" INITRD_ROOT="build/initrd_root_v3" \
    ISO="build/iso-v3.iso" ISO_ROOT="build/iso_root_v3" >/dev/null 2>&1; then
    fail "could not build the v3 image"
    exit 1
fi

LOG="${BHASKIX_BOOT_LOG:-$(mktemp)}"
OUT="$(mktemp)"
trap 'rm -f "$OUT"; [[ -z ${BHASKIX_BOOT_LOG:-} ]] && rm -f "$LOG"' EXIT
BHASKIX_ISO="$REPO_ROOT/build/iso-v3.iso" BHASKIX_BOOT_LOG="$LOG" BHASKIX_LANE=busybox-v3 \
    tests/qemu/boot-test.sh "$MODE" > "$OUT" 2>&1
status=$?

plan="$(grep -aoE 'xstate +(offered .*|no xsave on this cpu.*)' "$LOG" | head -1 | sed -E 's/ +/ /g')"
if ! grep -qaE "xstate +offered .*; enabled x87 sse avx \(0x7\), 832 bytes" "$LOG"; then
    skip "this CPU gives the kernel no AVX to enable -- '${plan:-no xstate line}' -- so a v3 binary proves nothing here; CI's QEMU 10.2.1 max and KVM judge it"
    exit 0
fi
if grep -qF "hi from sh" "$LOG"; then
    pass "the x86-64-v3 BusyBox ran its sh and printed, with AVX enabled: ${plan#xstate }"
else
    fail "the x86-64-v3 BusyBox did not run, with AVX enabled -- run 874's failure, which AVX state was to end"
    grep -aE "BusyBox|busybox|#UD|invalid opcode" "$LOG" | head -5 | sed 's/^/      /'
    exit 1
fi
if (( status != 0 )); then
    fail "and the boot it ran in failed other gates:"
    sed 's/\x1b\[[0-9;]*m//g' "$OUT" | grep -E '^FAIL' | head -5 | sed 's/^/      /'
    exit 1
fi
pass "and every other gate of the $MODE lane passed on the v3 image"
