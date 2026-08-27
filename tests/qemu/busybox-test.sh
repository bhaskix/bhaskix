#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Types at BusyBox's shell and asserts on its replies — RFC 0053's lane.
#
# # THIS LANE FAILS TODAY, ON PURPOSE, AND IS NOT IN `make test`
#
# It fails at one assertion — *"the reply came after BusyBox was done"* — and
# that is the true state of the machine rather than a broken test. A shell has
# to **wait** for a key, and `bin/linuxd` can only ask whether one is *already*
# waiting: `POLL_INPUT` answers "nothing yet", BusyBox gets `EAGAIN` and exits,
# and the line typed at it is answered by the Bhaskix shell that starts
# afterwards.
#
# Waiting properly means parking the caller and waking it when input arrives — a
# `BLOCK_ON` reply against a notification the console signals — which is RFC
# 0053's remaining work. **A blocking take is not the answer**: `TAKE_INPUT`
# blocks the *calling* thread, which is the adapter's only one, so it stops the
# whole personality until somebody types. This lane is what found that.
#
# It is kept, and kept out of `make test`, because it is the thing that will say
# when the remaining work is done — and because it has already earned its place
# twice: it found the blocking stall, and it caught its own first assertion
# passing while the wrong shell answered.
#
# # Why this is its own harness
#
# Every other lane types at the *Bhaskix* shell. This one types at a **hosted
# Linux program**, and the two cannot share a boot: a console has one keyboard,
# and RFC 0053 gives it to one domain at a time precisely so that "who is being
# typed at" has a single answer. So the machine is booted with `busybox=sh`,
# which runs the corpus as an interactive shell and grants its domain the
# console; the Bhaskix shell starts afterwards, once BusyBox has exited and the
# grant has gone back.
#
# **The last assertion is the one that proves the grant is temporary.** BusyBox
# reading is easy to demonstrate; the machine still reaching its own prompt
# afterwards is what says the keyboard was returned rather than taken.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${BHASKIX_BUSYBOX_LOG:-$(mktemp)}"
FIFO="$(mktemp -u)"
TIMEOUT="${BUSYBOX_TEST_TIMEOUT:-240}"
ISO="$REPO_ROOT/build/bhaskix.iso"

status=0
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; }

cleanup() {
    exec 3>&- 2>/dev/null || true
    [[ -n "${qemu:-}" ]] && kill "$qemu" 2>/dev/null
    rm -f "$FIFO"
    # The image carries a command line no other lane wants, so it is put back
    # whatever happened here -- a lane that left `busybox=sh` behind would stop
    # the next boot in the middle of its self-tests.
    make -C "$REPO_ROOT" iso >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! make -C "$REPO_ROOT" iso CMDLINE="busybox=sh" >/dev/null 2>&1; then
    fail "could not build an image with busybox=sh"
    exit 1
fi
printf '\033[2m      image %s, built %s\033[0m\n' \
    "${ISO#"$REPO_ROOT"/}" "$(date -r "$ISO" '+%H:%M:%S' 2>/dev/null || echo unknown)"

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_device_list disks

mkfifo "$FIFO"
echo "booting with busybox=sh, up to ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$REPO_ROOT/build/domain-disk.img,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    -no-reboot -cdrom "$ISO" -boot d -serial stdio -display none \
    < "$FIFO" > "$LOG" 2>&1 &
qemu=$!
exec 3> "$FIFO"

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

# The grant first: if the keyboard was not handed over there is no point typing,
# and the failure is a different one worth naming.
if await "this domain was granted the console"; then
    pass "the BusyBox domain was granted the console"
else
    fail "the console was never granted -- nothing here could have been typed at"
    status=1
fi

# Then BusyBox's own prompt. Typing before it is printed races the gap between
# the banner and the read, which is the mistake shell-test.sh records having
# made and which fails as a first line that never echoes.
if await "/ #"; then
    pass "BusyBox's sh reached its prompt"
else
    fail "BusyBox's sh never reached a prompt"
    status=1
fi

# **The assertion this lane exists for, and it must not be able to pass for the
# wrong reason.**
#
# `echo typed at busybox` is a command *both* shells understand. The first
# version of this check simply waited for the reply and passed -- on a run where
# BusyBox never read a byte, exited, and the **Bhaskix** shell answered the line
# instead. The log said `bhaskix$ echo typed at busybox` and the lane called it
# a success.
#
# So the reply must arrive **while BusyBox still holds the console**, which is
# before the corpus prints its summary and long before the Bhaskix shell greets
# anybody. Position is what tells the two apart, and nothing else here can.
printf 'echo typed at busybox\r' >&3
if await "typed at busybox"; then
    replied=$(grep -an 'typed at busybox' "$LOG" | head -1 | cut -d: -f1)
    corpus=$(grep -an 'busybox      ' "$LOG" | head -1 | cut -d: -f1)
    if [[ -n "$replied" && -n "$corpus" && "$replied" -lt "$corpus" ]]; then
        pass "a hosted program read a line typed at the machine and ran it"
    else
        fail "the reply came after BusyBox was done -- the Bhaskix shell answered, not BusyBox"
        status=1
    fi
else
    fail "BusyBox never saw what was typed at it"
    status=1
fi

# And give it back. `exit` ends the shell, its domain ends, and the grant is
# released with it -- which the next assertion is what checks.
printf 'exit\r' >&3
if await "Nothing left to do at this milestone"; then
    pass "the machine finished booting after BusyBox exited, so the keyboard came back"
else
    fail "the boot did not finish -- the grant may not have been released"
    status=1
fi

exec 3>&-
wait "$qemu" 2>/dev/null

if [[ $status -ne 0 ]]; then
    printf '\033[2mnote\033[0m  the serial log of this failing run is kept at %s\n' "$LOG" >&2
    exit 1
fi
echo
echo "  BusyBox answered what was typed at it"
