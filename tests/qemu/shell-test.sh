#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M6-04 and M6-05, as an executable check: does the machine answer when it is
# typed at, and is the thing answering unprivileged?
#
# Every other test in this project reads what the kernel says. This one also
# *writes* to it, over the same serial line, and asserts on the replies. That
# is the whole point: the console gained an input path, and an input path can
# only be tested by using it.
#
#   tests/qemu/shell-test.sh
#
# The boot self-test already proves a byte can arrive by interrupt -- it uses
# the UART's loopback mode, so it needs nobody to type. This proves the rest of
# the chain that loopback cannot: a real byte from outside the machine, through
# the I/O APIC, the vector, the ring, a capability, an endpoint, a service, a
# reply, and back out again as the answer to a command typed at a program in
# ring 3.
#
# What the machine boots to is the *user-mode* shell, which reaches the console
# and the filesystem only through the two capabilities it was given. Passing
# `kernel` runs the same conversation against the ring 0 shell instead, which
# needs an image built with `shell=kernel` on the command line.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
LOG="$(mktemp)"
# Longer than the boot tests', because this one waits for a whole boot *and*
# then holds a conversation with the machine, and every pause between typed
# lines is deliberate.
TIMEOUT="${SHELL_TEST_TIMEOUT:-240}"
MODE="${1:-user}"

fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }

[[ -f "$ISO" ]] || { fail "$ISO not found -- run 'make iso' first"; exit 1; }

# The ring 0 shell is selected on the kernel command line, which is baked into
# the image, so testing it means building one. The default image is put back
# afterwards -- a test that left a non-default image behind would make every
# later test in the run answer a question nobody asked.
if [[ "$MODE" == "kernel" ]]; then
    make -C "$REPO_ROOT" iso CMDLINE="shell=kernel" >/dev/null 2>&1 || {
        fail "could not build an image with shell=kernel"
        exit 1
    }
    restore_image() { make -C "$REPO_ROOT" iso >/dev/null 2>&1 || true; }
else
    restore_image() { :; }
fi

# What to type, once the prompt appears. `\r` rather than `\n`: a terminal
# sends a carriage return, and typing what a terminal actually sends is the
# point of this test.
#
# `nosuchcommand` is in the list on purpose. A shell that answered nothing at
# all would pass a test that only looked for command output it recognised.
if [[ "$MODE" == "kernel" ]]; then
    started="a shell. 'help' lists"
    commands=$'help\r'$'ls /\r'$'cat etc/hostname\r'$'elf bin/probe\r'$'nosuchcommand\r'
else
    started="a user-mode shell. 'help' lists"
    # `caps` is the one that matters: it asks the kernel about a slot this
    # program was not given, and the refusal comes from the kernel rather than
    # from a service saying no.
    commands=$'help\r'$'caps\r'$'ls /\r'$'cat etc/hostname\r'$'nosuchcommand\r'
fi

# A named pipe rather than a pipeline, for two reasons. QEMU does not exit
# when its stdin closes, so a pipeline would wait the whole timeout on every
# run -- pass or fail -- which is the coupling `boot-test.sh` had to remove
# once already. And holding the pipe open from this shell means the typing can
# be paced against what the machine has actually printed.
FIFO="$(mktemp -u)"
mkfifo "$FIFO"
trap 'rm -f "$LOG" "$FIFO"' EXIT

echo "booting and typing at it, up to ${TIMEOUT}s..."

timeout "$TIMEOUT" qemu-system-x86_64 \
    -M q35 -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    -no-reboot -cdrom "$ISO" -boot d -serial stdio -display none \
    < "$FIFO" > "$LOG" 2>&1 &
qemu=$!

# Opening for writing blocks until QEMU opens the read end, which is a useful
# synchronisation point in itself.
exec 3> "$FIFO"

# Waits for `$1` to appear in the log. Returns non-zero if it never does, or if
# the machine stopped waiting for it.
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

# Bytes typed before the shell exists are not lost -- they queue in the UART --
# but a test that raced would fail differently on a loaded machine.
if await "$started"; then
    while IFS= read -r -d $'\r' line; do
        printf '%s\r' "$line" >&3
        # One line at a time, with a pause, so each arrives as its own
        # interrupt. Sending them as one burst would exercise the FIFO drain
        # and never the blocking read.
        sleep 0.3
    done <<< "$commands"
    # The last command's reply is the signal that everything before it landed.
    await "nosuchcommand: not a command"
    sleep 0.5
fi

exec 3>&-
kill "$qemu" 2>/dev/null
wait "$qemu" 2>/dev/null

status=0

# Everything before the shell started is the boot self-test, which runs the
# same commands with no console input at all. Asserting against the whole log
# would therefore pass with the console input path entirely broken -- which is
# not a hypothetical: it did, when the wake-up was removed to check that this
# test could fail. Only the conversation counts.
SESSION="$(mktemp)"
trap 'rm -f "$LOG" "$FIFO" "$SESSION"' EXIT
sed -n "/$started/,\$p" "$LOG" > "$SESSION"

# Each check is a *reply* to something typed, not an echo of it. The shell
# echoes what arrives, so asserting on "help" alone would pass even if nothing
# ran it.
if [[ "$MODE" == "kernel" ]]; then
    checks=(
        "the shell started:a shell\. .help. lists"
        "the prompt appeared:bhaskix> "
        "a typed command was echoed and run:bhaskix> help"
        "help listed its commands:elf <path>"
        "ls read the filesystem:hello.txt"
        "cat read a file's contents:^bhaskix.?$"
        "elf parsed the user program:entry 0x10000000, 3 segments"
        "an unknown command was refused:nosuchcommand: not a command"
    )
else
    checks=(
        "the user-mode shell started:a user-mode shell"
        "the prompt appeared:bhaskix[$] "
        "a typed command was echoed and run:bhaskix[$] help"
        "help listed its commands:caps              what this program is allowed to do"
        # The line the milestone is about. Two capabilities work; a slot this
        # program was never given is refused by the kernel, before any service
        # is reached -- and it says so in different words.
        "the console capability works:0  console   reachable"
        "the filesystem capability works:1  files     reachable"
        "a slot it was not given is refused:2 +[(]nothing[)] no authority"
        "ls read the filesystem through IPC:hello.txt"
        "cat read a file through IPC:^bhaskix.?$"
        "an unknown command was refused:nosuchcommand: not a command"
    )
fi


for check in "${checks[@]}"; do
    name="${check%%:*}"
    marker="${check#*:}"
    if grep -qE -- "$marker" "$SESSION"; then
        pass "$name"
    else
        fail "$name -- '$marker' never appeared"
        status=1
    fi
done

# Nothing may have gone wrong on the way.
for marker in "KERNEL PANIC" "EXCEPTION" "FAILED" "unexpected interrupt on vector"; do
    if grep -qF -- "$marker" "$LOG"; then
        fail "'$marker' in the log"
        status=1
    fi
done

restore_image

if [[ $status -ne 0 ]]; then
    echo "--- serial log ---" >&2
    cat "$LOG" >&2
fi

exit $status
