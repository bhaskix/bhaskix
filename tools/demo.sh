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
DOMAIN_DISK="$REPO_ROOT/build/domain-disk.img"

bold=$'\033[1m'; dim=$'\033[2m'; green=$'\033[92m'; cyan=$'\033[96m'; off=$'\033[0m'

[[ -f "$ISO" ]] || { printf '%sno image at %s -- run `make demo`, which builds one%s\n' \
    "$bold" "${ISO#"$REPO_ROOT"/}" "$off" >&2; exit 1; }

command -v qemu-system-x86_64 >/dev/null || {
    printf '%squmu-system-x86_64 is not installed%s\n' "$bold" "$off" >&2
    printf 'On Debian or Ubuntu: %ssudo apt install qemu-system-x86%s\n' "$cyan" "$off" >&2
    exit 1
}

# **A fresh writable disk, for the reason the Makefile gives about it.** The
# domain disk is *written to* -- the filesystem service formats and journals on
# it -- so a second run starts from wherever the last one left off, and the
# block service's own self-test compares what it reads against what it wrote
# and reports FAILED. Every harness regenerates it; a demo that did not would
# show a newcomer two red lines caused by nothing but a previous demo.
rm -f "$DOMAIN_DISK"
make -C "$REPO_ROOT" "${DOMAIN_DISK#"$REPO_ROOT"/}" >/dev/null 2>&1 || true

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list full yes

cat <<BANNER

${bold}Bhaskix${off} ${dim}-- a capability operating system, booting in QEMU${off}

  ${dim}This is the same machine the gates run against: two disks, a network,
  an IOMMU containing them, and a USB keyboard. Boot takes a few seconds
  under emulation, and the report you are about to watch is the system
  checking itself -- every line is a claim it just tested.${off}

  ${bold}At the ${green}bhaskix\$${off}${bold} prompt, try:${off}

    ${cyan}help${off}         ${dim}what this shell can do${off}
    ${cyan}ls /${off}         ${dim}a real filesystem, reached through a capability${off}
    ${cyan}cat etc/hostname${off}
    ${cyan}ps${off}           ${dim}the domains this machine is running${off}
    ${cyan}pkg list${off}     ${dim}what is installed${off}
    ${cyan}dmesg${off}        ${dim}the boot report again, a page at a time${off}

  ${dim}To leave: press ${off}${bold}Ctrl-A${off}${dim} then ${off}${bold}x${off}${dim}.
  Nothing here touches your machine -- it is an emulator with two disk
  images under build/, and closing it discards everything.${off}

BANNER

# `-serial stdio` and no display: the console *is* this terminal, which is
# also how every harness talks to the machine. No timeout, because a person
# is driving.
exec qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M -no-reboot \
    -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$DOMAIN_DISK,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    "${IOMMU_ARGS[@]}" \
    -cdrom "$ISO" -boot d \
    -serial stdio -display none
