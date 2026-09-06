#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0074 step 4: a bond over two ports, and a member taken away underneath it.
#
#   tests/qemu/bond-test.sh
#
# Every other network lane proves the stack works while nothing goes wrong. This
# one takes a member's link down in the middle of a boot and asks whether the
# machine noticed, selected the other one, and went on carrying traffic. That
# cannot be tested from inside the guest: something outside has to pull the
# cable, and QEMU's monitor is the only hand available.
#
# **The monitor is a control channel, not a device.** `devices.sh` describes
# what the machine is made of; `-qmp` is how this harness reaches in and changes
# something about a machine already running, which is this lane's whole subject.
# Every harness already brings its own `-serial`, `-cdrom` and `-M` for the same
# reason.
#
# It talks QMP over TCP rather than a socket file, because bash can open a TCP
# connection by itself (`/dev/tcp`) and cannot open a unix one -- so this needs
# no `socat`, no `nc`, and no python that CI would have to be given.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
TIMEOUT="${BOND_TEST_TIMEOUT:-180}"
# How long the boot report waits for the failover after printing the bond it
# started with. Longer than this harness takes to notice the bond line and open
# the monitor, and shorter than the deadline above.
PATIENCE="${BOND_TEST_PATIENCE_MS:-60000}"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; RESET=$'\033[0m'
status=0
pass() { printf '  %sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() {
    printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$1" >&2
    printf '::error::bond-test: %s\n' "$1"
    status=1
}

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"

echo "building an image that waits ${PATIENCE}ms for a member to go down..."
make -C "$REPO_ROOT" iso CMDLINE="bhaskix.bond=$PATIENCE" >/dev/null 2>&1 \
    || { fail "could not build the image"; exit 1; }
restore_image() { make -C "$REPO_ROOT" iso >/dev/null 2>&1 || true; }
trap restore_image EXIT

[[ -f "$ISO" ]] || { fail "no image at $ISO"; exit 1; }

# **Translated, and that is not optional.** Without a unit neither port gets a
# DMA window, the driver is handed registers it cannot aim, and a bond with no
# members would fail for a reason that has nothing to do with bonding.
qemu_device_list full yes

MONITOR_PORT="$(bhaskix_pick_free_port)" || MONITOR_PORT=45560
LOG="${BHASKIX_BOND_LOG:-$(mktemp)}"
: > "$LOG"

rm -f "$REPO_ROOT/build/sata-disk.img"
make -C "$REPO_ROOT" build/sata-disk.img >/dev/null 2>&1 || true

echo "booting with two ports, up to ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    "${IOMMU_ARGS[@]}" \
    -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$REPO_ROOT/build/domain-disk.img,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    -qmp "tcp:127.0.0.1:$MONITOR_PORT,server=on,wait=off" \
    -no-reboot -cdrom "$ISO" -boot d -serial "file:$LOG" -display none >/dev/null 2>&1 &
qemu=$!

await() {
    local marker="$1" waited=0
    while ! grep -qF -- "$marker" "$LOG" 2>/dev/null; do
        kill -0 "$qemu" 2>/dev/null || return 1
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((TIMEOUT * 4)) ]] && return 1
    done
    return 0
}

# The cable, pulled. `set_link` is QEMU's own name for it and takes the netdev's
# id, which is `devices.sh`'s `net0` -- the member the bond starts on.
pull_the_cable() {
    exec 3<>"/dev/tcp/127.0.0.1/$MONITOR_PORT" || return 1
    # The greeting, then the handshake QMP requires before it will take a
    # command, then the command itself. Each answer is read so the connection
    # is not closed underneath a reply in flight.
    head -n 1 <&3 >/dev/null
    printf '{"execute":"qmp_capabilities"}\n' >&3
    head -n 1 <&3 >/dev/null
    printf '{"execute":"set_link","arguments":{"name":"net0","up":false}}\n' >&3
    local answer
    answer="$(head -n 1 <&3)"
    exec 3<&-
    [[ "$answer" == *'"return"'* ]]
}

if await "net bond       2 member(s)"; then
    pass "the bond came up with two members"
else
    fail "the machine never reported a bond with two members -- with one port there is nothing to fail over to"
fi

if [[ $status -eq 0 ]]; then
    if pull_the_cable; then
        pass "the monitor took the first member's link down"
    else
        fail "QEMU's monitor would not take the link down; nothing was tested"
    fi
fi

await "net bond       failed over" || true
kill -0 "$qemu" 2>/dev/null && kill "$qemu" 2>/dev/null
wait "$qemu" 2>/dev/null

before="$(grep -m1 'net bond' "$LOG" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//')"
after="$(grep 'net bond' "$LOG" | sed -n '2p' | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//')"

if [[ "$before" == *"traffic on port 0"* ]]; then
    pass "before: $before"
else
    fail "the bond did not start on port 0: ${before:-nothing was reported}"
fi

if [[ "$after" == *"failed over"* && "$after" == *"traffic on port 1"* ]]; then
    pass "after:  $after"
else
    fail "the bond did not fail over to port 1: ${after:-nothing was reported}"
fi

if [[ "$after" == *"have crossed since"* ]]; then
    pass "traffic continued across the member being downed"
else
    fail "nothing crossed after the failover: the bond selected a member that carries nothing"
fi

if [[ $status -ne 0 ]]; then
    grep -E "net |iommu window" "$LOG" | tail -25 >&2
elif [[ -z ${BHASKIX_BOND_LOG:-} ]]; then
    rm -f "$LOG"
fi
exit $status
