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
# # One unexplained run, recorded rather than forgotten
#
# On 2026-08-28 one run in eight abandoned the typed line mid-word: BusyBox
# echoed `echo` and then `^C`, which is what its line editor prints when a read
# comes back wrong, and read the rest as a fresh command. It has not recurred in
# the seven runs since.
#
# **The instrument that would have diagnosed it did not exist on that run.**
# Every way a park can be refused is counted in the nucleus, and a refusal
# answers `EAGAIN` -- which is exactly what would produce this. Those counters
# were printed with the other personality figures, which run before the console
# line is even claimed, so they could only ever have read zero. They are printed
# at the end of the interactive corpus now (`input park`), and every run since
# reports parks and **no** refusals. If this returns, that line is where to look
# first.
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

# `await` without the complaint: a pattern that never arrives is an answer here
# rather than a failure, because whether BusyBox asks for the cursor position
# depends on what it believes about the terminal.
await_quiet() {
    local tries=0
    while ((tries < 30)); do
        grep -qa -- "$1" "$LOG" 2>/dev/null && return 0
        sleep 0.5
        ((tries++))
    done
    return 1
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
# **No `p` in this line, and that is a measured working-around of the program
# rather than a stylistic choice.** This BusyBox binary does not put byte 0x70
# from its standard input into the line it is building: `p` alone, of every
# byte in a-z, A-Z and 0-9, is read and discarded. The delivery path was proved
# correct before the phrase was changed -- the nucleus was instrumented to log
# every byte `POLL_INPUT` hands out (all five `p`s of `echo ppqpprp busybox`
# appeared), no park and no refused copy occurred, and substituting 0x71 for
# 0x70 in the adapter made every one of them land and print. See TRACKER's
# entry for 2026-08-28. Typing a `p` here would fail this lane for a fault
# that is not the machine's.
# **Answer the cursor-position report first, because this harness is the
# terminal.** Once `poll` was answered (RFC 0055), BusyBox's line editor began
# doing the handshake a terminal is expected to complete: it writes `ESC [ 6 n`
# and waits to be told the cursor's row and column. Nothing replied, so the next
# thing typed was consumed as the reply and the command never arrived -- which
# presents as "BusyBox never saw what was typed" and is really "the terminal did
# not answer a question it was asked".
#
# Conditional, because typing this when nothing asked for it would put five
# stray bytes on the command line. Row 1, column 3, which is where the cursor
# actually is after `/ # `.
if await_quiet $'\033\[6n'; then
    printf '\033[1;3R' >&3
    sleep 1
fi

printf 'echo keyed at busybox\r' >&3
if await "keyed at busybox"; then
    replied=$(grep -an 'keyed at busybox' "$LOG" | head -1 | cut -d: -f1)
    # **Nothing had prompted `bhaskix` yet**, which is what says BusyBox
    # answered and not the shell that starts after it.
    #
    # `echo` is a command *both* shells understand, so the reply alone proves
    # nothing: the first version of this assertion passed on a run where
    # BusyBox never read a byte, exited, and the Bhaskix shell ran the line --
    # the log said `bhaskix$ echo typed at busybox` and the lane called it a
    # success.
    #
    # Comparing against the corpus summary was the second attempt and was wrong
    # for a subtler reason: this runs the moment the reply appears, while
    # BusyBox is still alive, so the interactive corpus has not printed its
    # summary yet and the only one in the log is the *earlier* non-interactive
    # pass. The check compared against a line printed long before anything was
    # typed and failed a passing machine.
    #
    # A prompt that has not happened cannot be raced: the Bhaskix shell greets
    # and prompts before it can echo anything, so if no `bhaskix` prompt
    # precedes the reply, it was not the one that answered.
    greeted=$(head -n "$replied" "$LOG" | grep -acE 'bhaskix[$>] ' || true)
    if [[ -n "$replied" && "$greeted" -eq 0 ]]; then
        pass "a hosted program read a line typed at the machine and ran it"
    else
        fail "the Bhaskix shell had already prompted, so it answered and BusyBox did not"
        status=1
    fi
else
    fail "BusyBox never saw what was typed at it"
    status=1
fi

# **And it was never told a lie about `poll`** -- RFC 0055.
#
# Asserted after the typing rather than before, because the interesting calls
# are the ones a shell makes *while reading a line*: BusyBox polled once per
# keystroke and printed this once per keystroke. A machine that answers `poll`
# says nothing here at all.
if grep -aq 'poll: Function not implemented' "$LOG"; then
    fail "BusyBox was told poll is not implemented, once per keystroke"
    status=1
else
    pass "poll was answered, so nothing complained about it"
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
