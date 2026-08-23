#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Types at the machine over **USB**, not over serial and not at the i8042.
#
# RFC 0041 step 7. `keyboard-test.sh` proved the i8042 path end to end; this is
# the same shape for the other keyboard, and it fails if any single link of a
# much longer chain is missing: the controller found and refused unless caged,
# brought up, its rings answering, a port enumerated, a slot taken, the device
# addressed, its descriptors read and parsed as a boot keyboard, the interrupt
# endpoint configured and Running, an MSI-X entry claimed, a Normal TRB queued,
# the doorbell rung on Device Context Index 3, a Transfer Event delivered, the
# report translated from *state* to *newly pressed*, and the byte published into
# the console ring the shell reads.
#
# **The machine is the `usb` profile, and it has no i8042 keystrokes to fall
# back on.** It has an i8042 controller -- q35 always does -- but QEMU delivers
# a key to one keyboard, and with a USB keyboard present that is the USB one.
# That was measured on 2026-08-23, by pointing `keyboard-test.sh` at a machine
# containing a USB keyboard and watching three of its five gates fail. So a key
# arriving here came over USB; there is nowhere else it could have come from.
#
# It deliberately does not type over serial at any point, for the reason
# `keyboard-test.sh` gives: a test that could fall back to the UART would pass
# on a machine whose keyboard does nothing.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
DISK="$REPO_ROOT/build/initrd.tar"
DISK2="$REPO_ROOT/build/domain-disk.img"
TIMEOUT="${TIMEOUT:-180}"
LOG="${BHASKIX_USB_KEYBOARD_LOG:-$(mktemp)}"
MONITOR="$(mktemp -u)"

# **The device list is `devices.sh`'s, not this file's**, and a gate enforces
# it: a harness that writes its own list drifts from every other harness, and
# the drift is invisible from either side. This one wants the `usb` profile,
# asked for **translated**: RFC 0038's rule 1 refuses a controller that is not
# behind an IOMMU, so an untranslated machine would refuse it correctly and
# leave this harness nothing to type at -- a failure for the reason the system
# is working.
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list usb yes

status=0
pass() { printf '\033[1;32mok\033[0m    %s\n' "$1"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$1"; }

[[ -f $ISO ]] || { fail "no image at $ISO -- run make iso"; exit 1; }

echo "booting and typing at its USB keyboard, up to ${TIMEOUT}s..."

timeout "$TIMEOUT" qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    "${IOMMU_ARGS[@]}" \
    -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$DISK2,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    -no-reboot -cdrom "$ISO" -boot d \
    -serial "file:$LOG" -display none \
    -monitor "unix:$MONITOR,server,nowait" &
qemu=$!

cleanup() {
    kill "$qemu" 2>/dev/null
    wait "$qemu" 2>/dev/null
    rm -f "$MONITOR"
}
trap cleanup EXIT

# Waits for an extended regex to appear in the log.
#
# A regex rather than a fixed string, and one call rather than `await A ||
# await B`: the alternation form serialises, so waiting for a marker that never
# arrives burns the whole timeout before the second is tried -- and by then the
# machine has been killed and there is nothing left to type at. That cost this
# harness its first run.
await() {
    local pattern="$1" waited=0
    while ! grep -qaE -- "$pattern" "$LOG" 2>/dev/null; do
        kill -0 "$qemu" 2>/dev/null || return 1
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((TIMEOUT * 4)) ]] && return 1
    done
    return 0
}

# Waits for a regex to appear in the log *after* line `$2`.
#
# **Every assertion about typing must be of this form.** The boot report is
# thousands of lines and a self-test runs the kernel shell's `help` during it,
# so the plain text of what this harness types -- `help`, and the help output
# itself -- is already in the log before a single key is sent. Two assertions
# passed that way on the first run, on a machine whose monitor socket had never
# even been opened. A marker that was already there proves nothing.
await_after() {
    local pattern="$1" from="$2" waited=0
    while ! tail -n "+$((from + 1))" "$LOG" 2>/dev/null | grep -qaE -- "$pattern"; do
        kill -0 "$qemu" 2>/dev/null || return 1
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((TIMEOUT * 4)) ]] && return 1
    done
    return 0
}

# Sends monitor commands, one per argument.
#
# Python rather than socat, which is not installed everywhere, and rather than
# `nc`, whose unix-socket flag differs between the two implementations that ship
# under that name.
monitor() {
    python3 - "$MONITOR" "$@" <<'PY'
import socket, sys, time
path, commands = sys.argv[1], sys.argv[2:]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for attempt in range(100):
    try:
        s.connect(path)
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("monitor socket never appeared")
time.sleep(0.2)
for command in commands:
    s.sendall((command + "\n").encode())
    # The endpoint is polled every 8 ms and this driver queues one transfer at
    # a time, so a key pressed while the previous report is still in flight is
    # a key this driver has not been built to catch. Typing slower than that is
    # the harness declining to test something step 7 does not claim.
    time.sleep(0.12)
time.sleep(0.5)
s.close()
PY
}

# The keyboard must have been found before anything can be typed at it. This is
# also the assertion that matters most on real hardware, where it is the
# difference between "no keyboard" and "a keyboard nobody can explain".
# The whole chain must have completed before anything can be typed. This one
# line stands for eleven steps of RFC 0041, and if it is missing the log above
# it says which of them stopped.
if await "usb keyboard   reading reports"; then
    pass "a USB keyboard was enumerated, configured, and its interrupt claimed"
else
    fail "no USB keyboard was reported before the timeout"
    grep -aE "xhci|usb keyboard" "$LOG" | sed 's/^/      /'
    status=1
fi

# Either shell will do: this is a test of the input path, not of which shell
# happens to be running. One pattern, for the reason `await` gives.
if await 'bhaskix[>$] '; then
    pass "a shell reached its prompt"
else
    fail "no prompt appeared"
    status=1
fi

if [[ $status -eq 0 ]]; then
    # Everything below is asserted against text produced *after* this line.
    mark=$(wc -l < "$LOG")

    # `help`, typed one key at a time as scancodes, then Enter.
    monitor "sendkey h" "sendkey e" "sendkey l" "sendkey p" "sendkey ret"

    # The echo proves the byte reached the shell's line editor; the answer
    # proves the line was run. Both, because an echo alone would pass with a
    # shell that never executes anything.
    if await_after 'bhaskix[>$] help' "$mark"; then
        pass "keys typed at the USB keyboard reached the shell and were echoed"
    else
        fail "the shell never saw the typed command"
        status=1
    fi
    if await_after 'print the arguments' "$mark"; then
        pass "the shell ran the command typed at its keyboard"
    else
        fail "the command echoed but never ran"
        status=1
    fi

    # Shift, because the modifier state is held between two scancodes and is
    # the part of the translation a table alone cannot get right.
    mark=$(wc -l < "$LOG")
    monitor "sendkey e" "sendkey c" "sendkey h" "sendkey o" "sendkey spc" \
        "sendkey shift-h" "sendkey i" "sendkey ret"
    if await_after '^Hi' "$mark"; then
        pass "a modifier is held across reports (a capital arrived over USB)"
    else
        fail "shift did not produce a capital -- the modifier state is wrong"
        status=1
    fi

    # **A held key must not repeat.** This is the whole difference between a
    # boot-protocol report and a scancode stream: the device sends the set of
    # keys currently held, every interval, whether anything changed or not. A
    # driver that treats each report as a keystroke turns one keypress into a
    # hundred and twenty-five a second. `sendkey` presses and releases, so what
    # this checks is that the run of reports in between produced exactly one
    # character.
    mark=$(wc -l < "$LOG")
    monitor "sendkey a" "sendkey ret"
    if await_after 'bhaskix[>$] a' "$mark"; then
        typed=$(tail -n "+$((mark + 1))" "$LOG" | grep -aoE 'bhaskix[>$] a+' | head -1)
        if [[ "$typed" =~ a{2,} ]]; then
            fail "a held key repeated: the driver is reading state as events ($typed)"
            status=1
        else
            pass "a held key produces one character, not one per report"
        fi
    else
        fail "the single keypress never arrived"
        status=1
    fi
fi

if [[ $status -ne 0 ]]; then
    echo "  last 30 lines:"
    tail -30 "$LOG" | sed 's/^/    /'
    echo "  log kept at $LOG"
else
    rm -f "$LOG"
fi
exit $status
