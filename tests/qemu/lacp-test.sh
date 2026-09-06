#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0074 step 5: two guests, one wire, and a bond that either forms or does
# not.
#
# Every other network gate in this project boots one machine against QEMU's
# built-in user-mode network, whose gateway answers ARP, ICMP and DHCP and
# knows nothing about 802.3ad. LACP cannot be tested that way at all: it needs
# a *partner*, something that runs the same state machine and answers. So this
# harness boots two Bhaskix guests joined by a socket netdev — QEMU's only
# netdev that carries raw frames from one guest to another — and reads what
# each one says its machine believes.
#
#   tests/qemu/lacp-test.sh
#
# **What it proves and what it cannot.** It proves that this implementation
# converges with a conforming partner, because the partner is another copy of
# it. It does not prove the SR550's switch will aggregate with it; RFC 0073
# records why that machine has never answered, and it is not a dependency of
# this row.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
# Two whole boots, one of which waits for the other's driver, and then a
# conversation that only advances when a frame arrives.
TIMEOUT="${LACP_TEST_TIMEOUT:-180}"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; RESET=$'\033[0m'
status=0

pass() { printf '  %sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() {
    printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$1" >&2
    printf '::error::lacp-test: %s\n' "$1"
    status=1
}

# **The image is built here, with a flag, and rebuilt without it afterwards.**
#
# The boot report is one snapshot, and a bond is not formed at a fixed instant:
# two machines have to boot, learn their addresses and exchange LACPDUs. Read at
# a fixed point the answer is a coin toss -- the first attempt at this step saw
# the same input print "speaking, and nothing has answered" once and nothing at
# all on the next run. `bhaskix.lacp=<ms>` tells the report to wait for the bond
# rather than to glance at it, which turns the question into one with the same
# answer twice.
#
# Every other lane leaves the flag off and pays nothing, because every other
# lane has no partner and would spend the whole window finding that out. The
# default image is put back at the end so this harness leaves `build/` as it
# found it, whatever order the suite runs in.
PATIENCE="${LACP_TEST_PATIENCE_MS:-60000}"
echo "building an image that waits ${PATIENCE}ms for the bond..."
make -C "$REPO_ROOT" iso CMDLINE="bhaskix.lacp=$PATIENCE" >/dev/null 2>&1 \
    || { fail "could not build the image"; exit 1; }
restore_image() { make -C "$REPO_ROOT" iso >/dev/null 2>&1 || true; }
trap restore_image EXIT

[[ -f "$ISO" ]] || { fail "no image at $ISO"; exit 1; }

# **The device list is `devices.sh`'s.** This harness chooses a *profile* and a
# role; it does not describe a machine. The rule and the reason are in that
# file's header, and a check enforces it.
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"

# One port for the pair, picked the same way the forwarded ports are, so two
# runs of this harness on one host do not collide.
export BHASKIX_PAIR_PORT="${BHASKIX_PAIR_PORT:-$(bhaskix_pick_free_port)}"

listen_log="$(mktemp)"; connect_log="$(mktemp)"

boot() {
    local role="$1" logfile="$2"
    BHASKIX_PAIR_ROLE="$role" qemu_device_list paired yes
    : > "$logfile"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-2}" -m 256M \
        "${IOMMU_ARGS[@]}" \
        -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
        "${VIRTIO_ARGS[@]}" \
        -no-reboot -cdrom "$ISO" -boot d \
        -serial "file:$logfile" -display none >/dev/null 2>&1 &
    printf '%s' "$!"
}

# The listener first: `socket,connect=` fails outright if nothing is listening,
# while `socket,listen=` waits. That ordering is the whole synchronisation.
echo "booting two guests on one wire, up to ${TIMEOUT}s..."
listener=$(boot listen "$listen_log")
for _ in $(seq 1 40); do
    ss -ltn "sport = :$BHASKIX_PAIR_PORT" 2>/dev/null | grep -q LISTEN && break
    sleep 0.25
done
connector=$(boot connect "$connect_log")

# Both machines print their boot report and then run a shell; there is nothing
# to type at, so the gate is the report line and the deadline is the machine's.
await_both() {
    local marker="$1" waited=0
    while :; do
        if grep -qF -- "$marker" "$listen_log" 2>/dev/null \
            && grep -qF -- "$marker" "$connect_log" 2>/dev/null; then
            return 0
        fi
        kill -0 "$listener" 2>/dev/null || return 1
        kill -0 "$connector" 2>/dev/null || return 1
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((TIMEOUT * 4)) ]] && return 1
    done
}

await_both "ipd lacp" || true

for pid in "$listener" "$connector"; do
    kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
done

# **Both machines, and both gates.** A bond is symmetric: a run where one side
# says it is aggregated and the other says nothing has answered is a run that
# found a bug, not half a pass.
for side in listen connect; do
    log="$listen_log"; [[ "$side" == connect ]] && log="$connect_log"
    if ! grep -q "ipd lacp" "$log"; then
        fail "$side guest never published an LACP state -- the machine either did not reach its serve loop or never learnt its own address"
        continue
    fi
    if grep -q "aggregated: synchronised, collecting and distributing" "$log"; then
        # The state it reached, not only that it reached one. A gate that prints
        # "ok" and nothing else cannot be read afterwards to see *what* passed,
        # and the flags are the whole content of the claim.
        pass "$side guest: $(grep -m1 'ipd lacp' "$log" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//')"
    else
        fail "$side guest did not aggregate: $(grep -m1 'ipd lacp' "$log" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//')"
    fi
done

if [[ $status -ne 0 ]]; then
    echo "--- listening guest ---" >&2
    grep -E "net |ipd " "$listen_log" | tail -20 >&2
    echo "--- connecting guest ---" >&2
    grep -E "net |ipd " "$connect_log" | tail -20 >&2
else
    rm -f "$listen_log" "$connect_log"
fi
exit $status
