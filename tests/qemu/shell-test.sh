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
# Overridable so a caller can keep the serial output. The test prints it only
# when something fails, which is right for a gate and unhelpful when what you
# want is to see what the machine actually said.
LOG="${BHASKIX_SHELL_LOG:-$(mktemp)}"
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
case "$MODE" in
kernel)
    cmdline="shell=kernel"
    ;;
disk)
    # The whole point of this mode: the filesystem is read off the block
    # device, so every file the shell touches -- including the shell itself,
    # which the kernel loaded before ring 3 existed -- came through the driver.
    cmdline="root=disk"
    ;;
*)
    cmdline=""
    ;;
esac

if [[ -n "$cmdline" ]]; then
    make -C "$REPO_ROOT" iso CMDLINE="$cmdline" >/dev/null 2>&1 || {
        fail "could not build an image with $cmdline"
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
    prompt="bhaskix> "
    commands=$'help\r'$'ls /\r'$'cat etc/hostname\r'$'elf bin/probe\r'$'disk\r'$'nosuchcommand\r'
else
    started="a user-mode shell. 'help' lists"
    prompt="bhaskix$ "
    # `caps` is the one that matters: it asks the kernel about a slot this
    # program was not given, and the refusal comes from the kernel rather than
    # from a service saying no.
    #
    # The four `open` lines are RFC 0015 step 4, and the order is the argument:
    # a name inside the directory held resolves; the same filesystem's other
    # names do not; a path is not a thing that can be asked for; and there is
    # no way to go up.
    commands=$'help\r'$'caps\r'$'map\r'$'irq\r'$'open inner\r'$'open greeting\r'
    commands+=$'open sub/inner\r'$'open ..\r'$'ls /\r'$'cat etc/hostname\r'
    if [[ "$MODE" == "iommu" ]]; then
        commands+=$'lend\r'
    fi
    commands+=$'nosuchcommand\r'
fi

# A named pipe rather than a pipeline, for two reasons. QEMU does not exit
# when its stdin closes, so a pipeline would wait the whole timeout on every
# run -- pass or fail -- which is the coupling `boot-test.sh` had to remove
# once already. And holding the pipe open from this shell means the typing can
# be paced against what the machine has actually printed.
FIFO="$(mktemp -u)"
mkfifo "$FIFO"
# The log survives when the caller named it: they asked for it, so removing it
# on the way out would answer a different question.
# The machine is stopped on the way out, not left to its own timeout. Without
# this every run leaks a four-CPU virtual machine for the rest of `$TIMEOUT`,
# so the suite's shell tests overlap each other -- and once there were four
# modes they overlapped enough to fail one on a loaded box. A test that is
# slower because an earlier test is still running is a test measuring the wrong
# thing, and one that *fails* for it is worse.
stop_machine() {
    if [[ -n ${qemu:-} ]]; then
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
    fi
}

if [[ -n ${BHASKIX_SHELL_LOG:-} ]]; then
    trap 'stop_machine; rm -f "$FIFO"' EXIT
else
    trap 'stop_machine; rm -f "$LOG" "$FIFO"' EXIT
fi

# The domain's disk is written to now, so it is rebuilt before every run.
# A fixture a test mutates is a fixture whose next run starts somewhere nobody
# chose, and this one carries the marker other checks look for in sector zero.
rm -f "$REPO_ROOT/build/domain-disk.img"
make -C "$REPO_ROOT" build/domain-disk.img >/dev/null 2>&1 || true

echo "booting and typing at it, up to ${TIMEOUT}s..."

# With a unit, the same flags RFC 0012's boot test uses. The block *service*
# only answers where one contains the device -- without it the driver cannot
# read a sector, so it exits rather than serving, which is the refusal working
# and is why RFC 0016 step 2's demonstration needs this mode to exist.
if [[ "$MODE" == "iommu" ]]; then
    IOMMU_ARGS=(-device intel-iommu,intremap=on)
    VIRTIO_ARGS=(-device virtio-blk-pci,drive=disk0,disable-legacy=on,iommu_platform=on
                 -device virtio-blk-pci,drive=disk1,disable-legacy=on,iommu_platform=on)
else
    IOMMU_ARGS=()
    VIRTIO_ARGS=(-device virtio-blk-pci,drive=disk0
                 -device virtio-blk-pci,drive=disk1)
fi

timeout "$TIMEOUT" qemu-system-x86_64 \
    -M q35 -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    "${IOMMU_ARGS[@]}" \
    -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$REPO_ROOT/build/domain-disk.img,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
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
# The banner, then the prompt, and the prompt is the one that matters.
#
# The banner is printed *before* the shell reaches its read; the prompt is
# printed from inside the loop that reads. Typing on the banner races the gap
# between them, and the first line is the one that loses -- which failed as
# "'bhaskix$ help' never appeared" on a loaded host, with every later command
# echoing correctly because by then the shell was reading.
if await "$started" && await "$prompt"; then
    first=1
    while IFS= read -r -d $'\r' line; do
        printf '%s\r' "$line" >&3

        # Paced by the machine, not by a clock.
        #
        # Every line is sent and then waited for, and the wait is for *this
        # line's echo*. Sending on a fixed interval assumed each command
        # finished inside it, which is true on an idle host and not on a busy
        # one -- three different checks have failed that way, each looking like
        # a different bug and all of them being this.
        #
        # The first line is also resent while it goes unanswered. The prompt is
        # printed before the shell reaches its read, and since RFC 0013 step 4
        # printing it is a round trip to another address space, so the gap
        # between "the prompt is in the log" and "the shell is reading" is
        # wide. Later lines are never resent: the bytes queue in the UART, and
        # a resent command would run twice.
        tries=0
        until grep -qF -- "$prompt$line" "$LOG" 2>/dev/null; do
            kill -0 "$qemu" 2>/dev/null || break
            ((tries += 1))
            ((tries > 40)) && break
            sleep 0.25
            if ((first)) && ((tries % 4 == 0)); then
                printf '%s\r' "$line" >&3
            fi
        done
        first=0
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
if [[ -n ${BHASKIX_SHELL_LOG:-} ]]; then
    trap 'rm -f "$FIFO" "$SESSION"' EXIT
else
    trap 'rm -f "$LOG" "$FIFO" "$SESSION"' EXIT
fi
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
        # RFC 0013 step 6: a program maps memory it holds, at an address of its
        # own choosing, and writes to it -- the first thing a driver in a
        # domain needs, since its rings are memory it holds and cannot fill in
        # without seeing.
        "a program maps memory it holds:3 +memory rw +mapped and holds what was written"
        # The same object, through a weaker capability. A refusal here is about
        # the *right* and not about the lookup, which is why the two
        # capabilities name one object.
        "a writable mapping is refused where only reading was granted:4 +memory ro +refused a writable mapping"
        # A page of *hardware*, reached from ring 3 through a capability and
        # nothing else. 15 is acknowledge|driver|features-ok|driver-ok: the
        # device agreeing that a driver brought it up, which is a value only a
        # mapping that reaches the hardware could return.
        "a program reads device registers through a capability:5 +device ro +status 15"
        "device registers cannot be written without the right:5 +device rw +refused a writable mapping"
        # The last link a driver in a domain needs: woken in ring 3 by a
        # notification, holding no vector and no way to reach an interrupt
        # controller. 45324 is 0xb10c, the badge the kernel signalled with.
        "a program in ring 3 is woken by a notification:6 +signal rd +woke with badge 45324"
        "a notification is a signal and not a queue:6 +signal rd +nothing left after taking it"
        "taking from a notification needs the right to:7 +signal wr +refused a take"
        # RFC 0016 step 1, from a program in ring 3. Slot 1's badge is what the
        # filesystem service uses to tell its callers apart, and until this was
        # fixed the holder could choose it. Both derivations are asked for in
        # one line because either alone proves nothing: the same badge with
        # weaker rights must work (delegation), and a different badge must not
        # (forgery). A kernel that refused both would read identically here to
        # one that refused neither.
        "a program cannot rename itself:1 +badge +can be passed on, and cannot be changed by its holder"
        "ls read the filesystem through IPC:hello.txt"
        "cat read a file through IPC:^bhaskix.?$"
        "an unknown command was refused:nosuchcommand: not a command"
    )
    # RFC 0016 step 2, and it only exists where there is a service to ask: two
    # programs in ring 3, one handing the other a capability. Four lines,
    # because each is a different rule and the mechanism is only worth having
    # if all four hold.
    if [[ "$MODE" == "iommu" ]]; then
        lend_checks=(
                # RFC 0015 step 4. The shell holds a capability to one directory --
                # `sub` -- and nothing naming the directory above it.
                "a directory is a capability:8 +directory +reachable"
                # What is *in* the directory held resolves, and the size comes from a
                # second invocation on the capability that came back rather than from
                # the lookup, so it is proof that the thing in the slot is the file.
                # A capability that outlived the directory it named. It resolves to
                # nothing rather than to whatever took the inode -- which is the bug
                # every filesystem with integer handles has had, and the check is here
                # before the step that can produce one for real.
                "a capability that outlived its directory resolves to nothing:10 +stale dir +the directory it named is gone"
                "a name inside the directory held resolves:inner: a file of 40 bytes"
                # The line the step exists for. `greeting` is on the same filesystem,
                # one level up, and the kernel reads it at boot -- and this program
                # cannot reach it, with no check to forget: it holds nothing that names
                # the directory it is in. The answer is the same one a name that exists
                # nowhere gets.
                "a name outside the directory held is unreachable:greeting: no such name in this directory"
                # There is no path resolver, so a path is not a thing that can be
                # asked. Refused as a name, because that is what it is.
                "a path is not a name this system resolves:sub/inner: not a name this system resolves"
                # And no way upwards. A capability to a directory that answered `..`
                # would be a capability to its parent, and so to everything, one level
                # at a time.
                "there is no way up out of a directory:[.][.]: not a name this system resolves"

            # A server cannot choose where its answer lands. Nothing was
            # declared, so nothing may arrive -- and the *call still
            # succeeded*, which is what makes this a refusal of the handing
            # rather than of the request.
            "a server cannot put a capability where it was not invited:undeclared +nothing was handed over"
            # And having been invited: the page arrives, and what is read out
            # of it is the device's own vendor and identity. No service told
            # this program that number; it mapped the page and looked.
            "a service handed a capability to a program in another domain:13 lent +a service handed over a page, and it reads 1af4:1042"
            # Holding a capability is not being allowed to give it away. Asked
            # while the service is answering, because outside a request it
            # would be refused for having no caller instead -- a different
            # rule, which is what the first version of this accidentally
            # tested.
            "a service cannot pass on a capability it may only hold:forbidden +a service cannot pass on what it may only hold"
            # And what arrived is no stronger than what was held.
            "a handed capability is no stronger than its original:13 lent +refused a writable mapping"
        )
        for check in "${lend_checks[@]}"; do
            checks+=("$check")
        done
    fi

    if [[ "$MODE" == "disk" ]]; then
        # Asserted against the whole log, not the session: this one is a line
        # the kernel printed before the shell existed, and it is what makes
        # every check above a statement about the disk.
        if grep -qE "root +[0-9]+ KiB read from the block device" "$LOG"; then
            pass "the filesystem was read off the block device"
        else
            fail "the root filesystem did not come from the disk"
            status=1
        fi
    fi
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
