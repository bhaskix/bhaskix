#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A bootable image of the native loader, for a machine rather than an emulator.
#
# `native-boot-test.sh` hands OVMF a FAT *directory* through QEMU's `fat:`
# device. A physical machine needs media, so this stages the same ESP -- the
# loader at the removable-media path, the kernel, the initrd, and a
# `boot.conf` when a command line is given -- into a FAT image, and wraps that
# as an El Torito UEFI ISO a service processor can mount as a virtual CD.
#
# The recipe was found by hand on 2026-08-22, for the SR550, and lived only in
# TRACKER's changelog until 2026-10-08. Two things that boot taught are kept
# here rather than rediscovered:
#
# - **Everything the loader reads must be inside the FAT image.** UEFI gives
#   the loader the El Torito image as its boot volume; it has no ISO 9660
#   driver, so a kernel beside the image on the CD is a kernel it cannot see.
# - **Size matters to a BMC.** One refused a 64 MiB image and accepted a
#   16 MiB one. The image is sized to the payload with a quarter spare, and
#   never below 16 MiB.
#
# The staging is fresh every run: on 2026-08-22 the first native image was
# built from the lane's ESP directory after its negative arm had corrupted the
# kernel there, and the machine refused it, correctly.
#
# Usage: tools/native-iso.sh [OUT] [CMDLINE]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/build/bhaskix-native.iso}
CMDLINE=${2:-}
LOADER="$ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$ROOT/build/initrd.tar"

for f in "$LOADER" "$KERNEL" "$INITRD"; do
    [ -f "$f" ] || { echo "native-iso: $f is missing; build with make first" >&2; exit 1; }
done
for tool in mkfs.vfat mcopy xorriso; do
    command -v "$tool" >/dev/null || { echo "native-iso: $tool is not installed" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT" "$ESP/bhaskix" "$WORK/iso"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp "$KERNEL" "$ESP/bhaskix/kernel"
cp "$INITRD" "$ESP/bhaskix/initrd.tar"
if [ -n "$CMDLINE" ]; then
    printf 'cmdline=%s\n' "$CMDLINE" > "$ESP/bhaskix/boot.conf"
fi

bytes=$(du -sb "$ESP" | cut -f1)
mib=$(( bytes * 5 / 4 / 1048576 + 2 ))
[ "$mib" -ge 16 ] || mib=16
IMG="$WORK/iso/esp.img"
truncate -s "${mib}M" "$IMG"
mkfs.vfat -F 16 -n BHASKIX "$IMG" >/dev/null
mcopy -s -i "$IMG" "$ESP/EFI" "$ESP/bhaskix" ::/
xorriso -as mkisofs -quiet -R -J -e esp.img -no-emul-boot -o "$OUT" "$WORK/iso"

echo "native-iso: $OUT ($(stat -c %s "$OUT") bytes; a ${mib} MiB ESP holding kernel $(stat -L -c %s "$KERNEL"), initrd $(stat -L -c %s "$INITRD")${CMDLINE:+, cmdline \"$CMDLINE\"})"
