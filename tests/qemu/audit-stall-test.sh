#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0101 step 3: the audit log fails closed, and only where it should.
#
# One boot of an image built with `bhaskix.fault=audit-stall`: `bin/auditd`
# attaches and drains nothing, so the ring fills. The kernel's stall self-test
# then derives through the system call's own path until a derive is refused
# with AUDIT_FULL, and checks that a revocation and a domain's end still happen
# after the refusal -- refusing them would leave authority in place -- and that
# once the headroom kept for them is spent too, an operation that takes
# authority away proceeds and is counted as a gap.
#
# Its own lane, not a boot-test.sh mode: a machine whose audit log is full
# refuses every grant after the self-test, including the ones the rest of the
# boot's gates depend on, which is the design and not a defect to gate on.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1
TIMEOUT="${AUDIT_STALL_TIMEOUT:-240}"
WORK="$(mktemp -d)"
LOG="$WORK/stall.log"
status=0

pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*"; status=1; }

qemu=""
cleanup() {
    if [[ -n $qemu ]]; then
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
    fi
    # Leave a normal image behind, as fault-test.sh does, so the next lane is
    # not quietly booting a stalled audit log.
    make iso >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

if ! make iso CMDLINE="bhaskix.fault=audit-stall" >/dev/null 2>&1; then
    fail "the stalled image would not build"
    exit 1
fi

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list full yes
cp build/domain-disk.img "$WORK/domain.img"

echo "booting with bin/auditd told to drain nothing, up to ${TIMEOUT}s..."
# The machine is devices.sh's, as every lane's is: `check-one-machine.sh`
# refuses a device declared anywhere else.
qemu-system-x86_64 -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    "${IOMMU_ARGS[@]}" \
    -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$WORK/domain.img,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    -no-reboot -cdrom build/bhaskix.iso -boot d -serial "file:$LOG" -display none &
qemu=$!
for _ in $(seq 1 "$TIMEOUT"); do
    grep -aqE 'Bring-up complete|KERNEL PANIC' "$LOG" 2>/dev/null && break
    kill -0 "$qemu" 2>/dev/null || break
    sleep 1
done
sleep 2
clean=$(sed 's/\x1b\[[0-9;]*m//g; s/\r$//' "$LOG")

if grep -q 'KERNEL PANIC' <<< "$clean"; then
    fail "the kernel panicked: $(grep -m1 'KERNEL PANIC' <<< "$clean" | cut -c1-150)"
fi
if grep -qE 'audit +stalled on purpose \(bhaskix\.fault=audit-stall\): bin/auditd attached and drains nothing' <<< "$clean"; then
    pass "bin/auditd attached and drained nothing, as told"
else
    fail "the stall was not in effect: $(grep -m1 -a 'audit  ' <<< "$clean" | cut -c1-150)"
fi
stall=$(grep -m1 -aE 'audit stall' <<< "$clean")
if [[ $stall =~ a\ derive\ was\ refused\ with\ AUDIT_FULL\ after\ ([0-9]+)\ were\ recorded\;\ a\ revocation\ and\ a\ domain.s\ end\ still\ happened\ after\ it,\ and\ ([0-9]+)\ operation\(s\)\ proceeded\ unrecorded\ and\ were\ counted\;\ ([0-9]+)\ refused ]] \
        && ((BASH_REMATCH[1] > 0 && BASH_REMATCH[2] > 0 && BASH_REMATCH[3] > 0)); then
    pass "a full log refused a grant, and a revocation and an ending still happened: $(cut -c1-140 <<< "$stall" | sed 's/^ *//')..."
else
    fail "the audit log did not fail closed as it should: ${stall:-no stall self-test line}"
fi

if ((status)) && [[ -n ${BHASKIX_KEEP_LOGS:-} ]]; then
    mkdir -p "$BHASKIX_KEEP_LOGS"
    cp "$LOG" "$BHASKIX_KEEP_LOGS"/audit-stall.log
fi
exit $status
