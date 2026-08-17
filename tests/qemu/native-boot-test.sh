#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The native loader's lane -- RFC 0028, graduated on purpose.
#
# This script's gate list IS the honest statement of how far sovereignty
# has come: it grows a check per implemented step, and the roadmap's
# bhaskixboot bullet closes only when this lane runs the same gates the
# Limine lanes do. Today it proves step 1: the firmware starts our loader,
# and the first words on the serial wire are ours.
#
# Usage:
#   tests/qemu/native-boot-test.sh

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
LOG="${BHASKIX_NATIVE_BOOT_LOG:-$(mktemp)}"
TIMEOUT=30

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'

pass() { printf '%sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$1"; }

if [[ ! -f "$LOADER" ]]; then
    fail "bhaskixboot.efi is not built; make it first"
    exit 1
fi

# OVMF ships as a CODE/VARS pair and must be searched as one -- the same
# rule, and the same pair list, as boot-test.sh's uefi mode, for the same
# recorded reasons.
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
    if compgen -G "/usr/share/OVMF/*.fd" >/dev/null 2>&1 \
       || compgen -G "/usr/share/edk2/ovmf/*.fd" >/dev/null 2>&1; then
        fail "OVMF is installed but no complete CODE/VARS pair was found"
        exit 1
    fi
    printf '%sskip%s  native boot test (OVMF not installed)\n' "$YELLOW" "$RESET"
    exit 0
fi

# The ESP as a directory: QEMU's fat: driver serves it read-write, no image
# tooling needed, and EFI/BOOT/BOOTX64.EFI is the removable-media path every
# firmware falls back to.
ESP="$REPO_ROOT/build/native-esp"
rm -rf "$ESP"
mkdir -p "$ESP/EFI/BOOT"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"

WRITABLE_VARS="$REPO_ROOT/build/OVMF_VARS_native.fd"
cp "$OVMF_VARS" "$WRITABLE_VARS"

echo "booting the native loader under $(basename "$OVMF_CODE"), up to ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 256 -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -serial "file:$LOG" \
    >/dev/null 2>&1 &
QEMU_PID=$!

# Poll for the banner rather than waiting the whole timeout: step 1's
# loader returns to the firmware after speaking, and the firmware then
# wanders into its own shell -- the banner is the event, not the exit.
status=1
for _ in $(seq 1 "$TIMEOUT"); do
    if grep -q "bhaskixboot 0.0.0: the machine entered through our own door" "$LOG" 2>/dev/null; then
        status=0
        break
    fi
    sleep 1
done
kill "$QEMU_PID" >/dev/null 2>&1
wait "$QEMU_PID" 2>/dev/null

if [[ "$status" -eq 0 ]]; then
    pass "the firmware started our loader, and the first words on the wire were ours"
else
    fail "the native loader's banner never appeared"
    echo "--- serial log ---"
    cat "$LOG" 2>/dev/null | head -30
fi
exit "$status"
