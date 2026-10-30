#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Boots Bhaskix in QEMU and hands you its shell.
#
# **This is the front door.** Everything else in `tests/qemu/` boots the machine
# to *check* it and throws the console away; this boots the same machine and
# gives it to a person. The device list comes from `devices.sh` for the reason
# that file exists: two harnesses once built their own and drifted, and the
# machine a newcomer sees should be the machine the gates run against, not a
# reduced one that quietly does less.
#
# The full profile with translation on, which is the richest machine this
# system has: two disks, a network, an IOMMU containing them, and a USB
# keyboard on an xHCI controller. A bare machine boots faster and shows a shell
# that can do almost nothing, which is a worse first impression than a slower
# boot.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
DISK="$REPO_ROOT/build/initrd.tar"
# **The demo's own disk, not the tests' master** (2026-10-30). The harnesses
# delete and rebuild `build/domain-disk.img` before every run, which was
# harmless while every demo started fresh; now that a demo keeps its disk, a
# `make test` in between would quietly erase what a reader installed.
DOMAIN_DISK="$REPO_ROOT/build/demo-disk.img"

bold=$'\033[1m'; dim=$'\033[2m'; green=$'\033[92m'; cyan=$'\033[96m'; off=$'\033[0m'

[[ -f "$ISO" ]] || { printf '%sno image at %s -- run `make demo`, which builds one%s\n' \
    "$bold" "${ISO#"$REPO_ROOT"/}" "$off" >&2; exit 1; }

command -v qemu-system-x86_64 >/dev/null || {
    printf '%sqemu-system-x86_64 is not installed%s\n' "$bold" "$off" >&2
    printf 'On Debian or Ubuntu: %ssudo apt install qemu-system-x86%s\n' "$cyan" "$off" >&2
    exit 1
}

# **The writable disk is kept from one demo to the next** (RFC 0095, the
# lead's choice, 2026-10-30). Until that day every boot formatted it, so this
# script deleted it first: a second boot on a formatted disk reported two red
# lines caused by nothing but the previous demo. A boot now formats a disk only
# when it carries the project's marker and keeps one that holds this system's
# filesystem -- so a package installed in one demo is there in the next, which
# is the behaviour a newcomer should see. `make demo-fresh` (DEMO_FRESH=1)
# deletes it first, for a demo that starts from nothing.
if [[ -n ${DEMO_FRESH:-} ]]; then
    rm -f "$DOMAIN_DISK"
fi
if [[ -f "$DOMAIN_DISK" ]]; then
    disk_note="build/demo-disk.img, kept from your last demo, so what you
  installed is still there; \`make demo-fresh\` starts from a new one"
else
    # Made here, as the guides tell a reader to make theirs: the marker is
    # what lets a boot format it. Not copied from the tests' master, which
    # `shell-test.sh` boots and so may hold a filesystem rather than a marker.
    mkdir -p "$(dirname "$DOMAIN_DISK")"
    printf 'BHASKIX-DOMAIN-DISK-SECTOR-0' > "$DOMAIN_DISK"
    truncate -s 4M "$DOMAIN_DISK"
    disk_note="build/demo-disk.img, new: this boot formats it, and later
  demos keep it"
fi

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list full yes

cat <<BANNER

${bold}Bhaskix${off} ${dim}-- a capability operating system, booting in QEMU${off}

  ${dim}This is the same machine the gates run against: two disks, a network,
  an IOMMU containing them, and a USB keyboard. Boot takes about half a
  minute under emulation, and the report you are about to watch is the
  system checking itself -- every line is a claim it just tested.${off}

  ${dim}Its writable disk is ${disk_note}.${off}

  ${bold}At the ${green}bhaskix\$${off}${bold} prompt, try:${off}

    ${cyan}help${off}         ${dim}what this shell can do${off}
    ${cyan}ls /${off}         ${dim}a real filesystem, reached through a capability${off}
    ${cyan}cat etc/hostname${off}
    ${cyan}caps${off}         ${dim}what this shell is allowed to do${off}
    ${cyan}pkg list${off}     ${dim}what is installed${off}
    ${cyan}dmesg${off}        ${dim}the boot report again, a page at a time${off}

  ${dim}To leave: press ${off}${bold}Ctrl-A${off}${dim} then ${off}${bold}x${off}${dim}.
  Nothing here touches your machine -- it is an emulator with two disk
  images under build/; closing it keeps the writable one for next time.${off}

BANNER

# The serial console and no display: the console *is* this terminal, which is
# also how every harness talks to the machine. No timeout, because a person
# is driving.
#
# **`mon:stdio`, not `stdio`** (2026-10-30). The banner above says Ctrl-A then x
# leaves, and that key reaches QEMU only when its monitor shares the terminal;
# with plain `-serial stdio` the two keys went to the guest and QEMU ran on --
# measured that day, as were both halves of this sentence.
exec qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M -no-reboot \
    -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$DOMAIN_DISK,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    "${IOMMU_ARGS[@]}" \
    -cdrom "$ISO" -boot d \
    -serial mon:stdio -display none
