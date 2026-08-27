#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Types at the machine with a **keyboard**, not a serial line.
#
# Every other harness here reaches the shell through the UART, which is exactly
# why the keyboard gap survived so long: console input was a UART and nothing
# else, and no test could tell, because no test used anything else. A machine
# booted from a USB stick onto a laptop would have printed its whole boot report
# and then ignored every key pressed at it.
#
# So this drives QEMU's i8042 through the monitor's `sendkey`, which produces
# real scancodes on the real emulated controller. That makes it an end-to-end
# gate on the entire path RFC 0037 added -- the controller probed, the line
# claimed through the I/O APIC, the interrupt delivered, the port drained before
# it is acknowledged, set-1 scancodes translated, the byte published into the
# keyboard's own ring, the consumer merging two rings, the shell woken -- and it
# fails if any single link is missing.
#
# It deliberately does not type over serial at any point. A test that could fall
# back to the UART would pass on a machine whose keyboard does nothing.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
DISK="$REPO_ROOT/build/initrd.tar"
DISK2="$REPO_ROOT/build/domain-disk.img"
TIMEOUT="${TIMEOUT:-180}"
LOG="${BHASKIX_KEYBOARD_LOG:-$(mktemp)}"
MONITOR="$(mktemp -u)"

# **The device list is `devices.sh`'s, not this file's**, and a gate enforces
# it: a harness that writes its own list drifts from every other harness, and
# the drift is invisible from either side. This one wants the same machine the
# shell test boots, because it is testing the same shell.
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list disks

status=0
pass() { printf '\033[1;32mok\033[0m    %s\n' "$1"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$1"; }

[[ -f $ISO ]] || { fail "no image at $ISO -- run make iso"; exit 1; }

echo "booting and typing at its keyboard, up to ${TIMEOUT}s..."

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
    # The i8042 holds one byte at a time and the guest must take it before the
    # next arrives. Typing faster than a person is how this test would produce
    # dropped keys that are the harness's fault rather than the kernel's.
    time.sleep(0.08)
time.sleep(0.5)
s.close()
PY
}

# The keyboard must have been found before anything can be typed at it. This is
# also the assertion that matters most on real hardware, where it is the
# difference between "no keyboard" and "a keyboard nobody can explain".
if await "keyboard       i8042 present"; then
    pass "the i8042 controller was found and its line claimed"
else
    fail "no keyboard was reported before the timeout"
    grep -a "keyboard" "$LOG" | sed 's/^/      /'
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
        pass "keys typed at the keyboard reached the shell and were echoed"
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

    # **And ask the machine what it counted — RFC 0051.** This is the assertion
    # that could not be written before it: the counters live in the nucleus, and
    # the shell this lane types at runs in ring 3, so `input` answered *"not a
    # command"* here until 2026-08-27. The SR550's keyboard appeared dead that
    # day and nothing on the machine could say whether a key had reached it.
    #
    # The keyboard column must be **non-zero**, which is the whole point: keys
    # demonstrably arrived above, so a counter reading zero would mean the
    # count is not wired to the thing it claims to count -- exactly how
    # `set_owner` sat unwritten for a milestone.
    mark=$(wc -l < "$LOG")
    monitor "sendkey i" "sendkey n" "sendkey p" "sendkey u" "sendkey t" "sendkey ret"
    if await_after 'keyboard +[1-9][0-9]* bytes from [1-9][0-9]* i8042 scancodes' "$mark"; then
        pass "the input counters attribute what was typed to the keyboard"
    else
        fail "the keyboard's own counter did not move for keys that demonstrably arrived"
        status=1
    fi

    # Shift, because the modifier state is held between two scancodes and is
    # the part of the translation a table alone cannot get right.
    mark=$(wc -l < "$LOG")
    monitor "sendkey e" "sendkey c" "sendkey h" "sendkey o" "sendkey spc" \
        "sendkey shift-h" "sendkey i" "sendkey ret"
    if await_after '^Hi' "$mark"; then
        pass "shift is held across scancodes (a capital arrived)"
    else
        fail "shift did not produce a capital -- the modifier state is wrong"
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
