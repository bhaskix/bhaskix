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
# Set by the waiters below when QEMU is found gone. Everything after that point
# is unobservable, and saying so is the difference between a report and a guess.
MACHINE_GONE=0
pass() { printf '\033[1;32mok\033[0m    %s\n' "$1"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$1"; }

# An assertion that did not pass, and *why* it did not.
#
# **Its claim was being contradicted two lines later.** When the machine hangs
# and QEMU is killed at the timeout, every later wait fails and each printed a
# sentence of its own -- so `the shell never saw the typed command` sat directly
# above `ok the shell ran the command typed at its keyboard`, which cannot both
# be true. Nothing was wrong with the keyboard; the run had stopped. That sent a
# reader after input on 2026-09-14, and the comment further down records this
# same harness costing somebody a day the same way in August.
#
# A truncated log cannot support a claim about what the machine did, so it does
# not make one.
missed() {
    if [[ $MACHINE_GONE == 1 ]]; then
        fail "not observed -- the run was cut short before this point: $1"
    else
        fail "$1"
    fi
    status=1
}

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
        kill -0 "$qemu" 2>/dev/null || { MACHINE_GONE=1; return 1; }
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
# **A third argument bounds the wait, and the default is the whole budget.**
#
# Every wait here could spend `TIMEOUT` seconds, which is also QEMU's own
# deadline -- so the *first* pattern that could not match took the machine with
# it and left every assertion after it with nothing to read. On 2026-09-14 that
# turned one unmatched echo into three failing assertions and a defect report
# about a lane that "hangs one run in three". The lane was fine.
#
# Boot waits keep the full budget: a loaded runner really can take a minute to
# reach a prompt. A wait for something that should follow a keystroke gets
# `TYPED_WAIT`, so a miss costs that and the run carries on to say what else
# worked -- which is the difference between one honest failure and three.
TYPED_WAIT=25
await_after() {
    local pattern="$1" from="$2" budget="${3:-$TIMEOUT}" waited=0
    while ! tail -n "+$((from + 1))" "$LOG" 2>/dev/null | grep -qaE -- "$pattern"; do
        kill -0 "$qemu" 2>/dev/null || { MACHINE_GONE=1; return 1; }
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((budget * 4)) ]] && return 1
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
    missed "no USB keyboard was reported before the timeout"
    grep -aE "xhci|usb keyboard" "$LOG" | sed 's/^/      /'
fi

# RFC 0049. Every unit the firmware named is listed, and every one of them is
# programmed. This emulator describes exactly one, so these gates prove the
# enumeration runs and reports -- **not** that the multi-unit case works, which
# no emulator here can show. That was measured on an SR550, where the unit
# carrying INCLUDE_PCI_ALL was the fourth and had never been programmed.
if await "iommu unit 0   registers at .*claims every device"; then
    pass "every remapping unit the firmware named is listed"
else
    missed "the unit list did not report"
    grep -aE "iommu" "$LOG" | sed 's/^/      /'
fi

# The outcome, which is the claim that matters: not "a unit was found" but
# "every unit the firmware named is programmed". A machine where that is false
# has devices reaching all of memory while the report says they are contained.
if await "iommu          all 1 unit programmed"; then
    pass "every unit the firmware named was programmed"
else
    missed "the kernel did not report programming every unit"
    grep -aE "iommu" "$LOG" | sed 's/^/      /'
fi

# The other half: a fault line every boot, saying none rather than saying
# nothing. Silence here used to be indistinguishable from a check that did not
# run, which is what made a real DMA failure unreadable for four boots.
if await "iommu faults   .during bring-up. none recorded by the one programmed unit"; then
    pass "the IOMMU was asked about faults, and answered"
else
    missed "no fault line was printed"
fi

# The pre-OS handoff ran, and said what it found. On this emulator the answer
# is always "no legacy capability" -- QEMU's controller declares none, so there
# is no firmware to take it from. That makes this a weak assertion about
# *ownership* and a strong one about *reporting*: it fails if the handoff stops
# running, stops printing, or starts refusing a controller nobody claimed.
#
# **The branch that matters here cannot be reached on this machine.** Firmware
# holding the controller, and the SMI sources it arms, exist only on a real
# server -- which is exactly why an unenforced ownership contract survived until
# an SR550 hung on it. What this gate protects is the line that would have said
# so.
if await "xhci           no legacy capability"; then
    pass "the controller was asked for, and firmware had never claimed it"
else
    missed "the pre-OS handoff did not report"
    grep -aE "xhci" "$LOG" | sed 's/^/      /'
fi

# Either shell will do: this is a test of the input path, not of which shell
# happens to be running. One pattern, for the reason `await` gives.
if await 'bhaskix[>$] '; then
    pass "a shell reached its prompt"
else
    missed "no prompt appeared"
fi

if [[ $status -eq 0 ]]; then
    # Everything below is asserted against text produced *after* this line.
    mark=$(wc -l < "$LOG")

    # `help`, typed one key at a time as scancodes, then Enter.
    monitor "sendkey h" "sendkey e" "sendkey l" "sendkey p" "sendkey ret"

    # The echo proves the byte reached the shell's line editor; the answer
    # proves the line was run. Both, because an echo alone would pass with a
    # shell that never executes anything.
    # **The echo need not be on the prompt's line**, and requiring it was a
    # gate that failed for the wrong reason for a whole day. The console is
    # shared: any other domain that prints between the shell printing
    # `bhaskix$ ` and the shell echoing what was typed pushes the echo onto a
    # line of its own. RFC 0060's hosted probe does exactly that, and this
    # pattern then reported "the shell never saw the typed command" on a
    # machine where the shell had seen it, echoed it and run it.
    #
    # Staleness is still handled, and by the mechanism built for it: `mark`.
    # The boot report contains the word `help` and the help output long before
    # anything is typed, which is why the match is anchored *after* the mark
    # rather than to the prompt.
    # **The echo is not asserted, and that is a decision rather than a gap.**
    #
    # It was, twice, and produced two withdrawn defects in one day. The console
    # is shared by every domain, and the shell echoes a *character at a time* --
    # so another domain printing between two keystrokes splits the echo. The
    # first version required the echo on the prompt's line and was relaxed to
    # allow a line of its own; the case that finished it looks like this, from
    # a kept log on 2026-09-14:
    #
    #     hhosted change ok: made a directory, removed a file, and ...
    #     hosted exec busybox refused errno 2
    #     elp
    #
    # The typed `h` is prefixed to a probe's line and `elp` arrives three lines
    # later. No line-oriented pattern can match that, and because a wait runs
    # until the machine dies, one that cannot match spends the whole timeout and
    # takes every assertion after it down as well. That read as "the lane hangs
    # one run in three" and was filed as a defect. Nothing was hanging.
    #
    # **What is asserted instead is strictly stronger.** The help text contains
    # `print the arguments`, and it is printed only by a shell that received the
    # keystrokes, assembled them into a line, and ran it. Interleaving cannot
    # fake that, and no echo can satisfy it. What is given up is the claim that
    # the *echo* works, which a shared console cannot support at this
    # granularity from outside.
    if await_after 'print the arguments' "$mark" "$TYPED_WAIT"; then
        pass "keys typed at the USB keyboard reached the shell, which ran what they spelled"
    else
        missed "the shell never ran the typed command"
    fi

    # Shift, because the modifier state is held between two scancodes and is
    # the part of the translation a table alone cannot get right.
    mark=$(wc -l < "$LOG")
    monitor "sendkey e" "sendkey c" "sendkey h" "sendkey o" "sendkey spc" \
        "sendkey shift-h" "sendkey i" "sendkey ret"
    if await_after '^Hi' "$mark" "$TYPED_WAIT"; then
        pass "a modifier is held across reports (a capital arrived over USB)"
    else
        missed "shift did not produce a capital -- the modifier state is wrong"
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
    if await_after '(bhaskix[>$] a|^a)' "$mark" "$TYPED_WAIT"; then
        typed=$(tail -n "+$((mark + 1))" "$LOG" | grep -aoE 'bhaskix[>$] a+' | head -1)
        if [[ "$typed" =~ a{2,} ]]; then
            fail "a held key repeated: the driver is reading state as events ($typed)"
            status=1
        else
            pass "a held key produces one character, not one per report"
        fi
    else
        missed "the single keypress never arrived"
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
