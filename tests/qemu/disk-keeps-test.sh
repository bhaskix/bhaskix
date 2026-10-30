#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0095: a disk that keeps what was written, and leaves alone what is not
# the project's.
#
# Four boots of the same image:
#
#   1. a fresh disk carrying the project's marker: it is formatted, as every
#      disk was until 2026-10-30, and `hello.bpk` is installed on it;
#   2. **the same file, booted again, under `boot-test.sh`** -- every gate that
#      file applies to a fresh disk must pass on this kept one, with the block
#      service and the journal saying it was kept. Every gate, and not a
#      search for the word FAILED: the first version of this lane did that, and
#      its own arm showed a hosted probe answering `mkdir refused errno 17` in a
#      line with no FAILED in it, which that search could not see;
#   3. the same file a third time, typed at: the package boot 1 installed is
#      listed and runs, two reboots later;
#   4. a disk that is not the project's -- a header of somebody else's and
#      random bytes after it: **its sha256 must not change**, which is the only
#      assertion that can see a write nobody reports.
#
# Until RFC 0095 boot 2 failed (`block service FAILED`, and `0 installed`) and
# boot 4 formatted somebody's disk. Both were the boot's design, not a bug in
# any one line, which is why each is asserted here rather than reasoned about.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
TIMEOUT="${DISK_KEEPS_TIMEOUT:-240}"
WORK="$(mktemp -d)"
STARTED="a user-mode shell. 'help' lists"
PROMPT='bhaskix$ '
status=0

pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*"; status=1; }

[[ -f "$ISO" ]] || { echo "no image at $ISO -- run make" >&2; exit 1; }

qemu=""
stop_machine() {
    if [[ -n $qemu ]]; then
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
        qemu=""
    fi
}
trap 'stop_machine; rm -rf "$WORK"' EXIT

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
# The richest machine, as `make demo` boots it and `shell-test.sh iommu` does:
# the package manager only exists where there is a filesystem service to ask.
qemu_device_list full yes

# A domain disk as the Makefile makes one: the marker, then zeroes to 4 MiB.
make_marked_disk() {
    printf 'BHASKIX-DOMAIN-DISK-SECTOR-0' > "$1"
    dd if=/dev/zero bs=1 count=4194276 >> "$1" 2>/dev/null
}

# Boots with `$1` as the domain disk, logging to `$2`, and types each further
# argument at the prompt in turn, each paced by its own echo. Ends with a line
# whose answer proves everything before it was read.
boot_and_type() {
    local disk="$1" log="$2"
    shift 2
    local fifo="$WORK/fifo"
    rm -f "$fifo"
    mkfifo "$fifo"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
        "${IOMMU_ARGS[@]}" \
        -drive "file=$REPO_ROOT/build/initrd.tar,format=raw,if=none,id=disk0,readonly=on" \
        -drive "file=$disk,format=raw,if=none,id=disk1" \
        "${VIRTIO_ARGS[@]}" \
        -no-reboot -cdrom "$ISO" -boot d -serial stdio -display none \
        < "$fifo" > "$log" 2>&1 &
    qemu=$!
    exec 3> "$fifo"
    await() {
        local waited=0
        while ! grep -qF -- "$1" "$log" 2>/dev/null; do
            kill -0 "$qemu" 2>/dev/null || return 1
            sleep 0.25
            waited=$((waited + 1))
            [[ $waited -gt $((TIMEOUT * 4)) ]] && return 1
        done
        # Explicit: a `while` answers with the last status its body produced,
        # which here is the false test above -- so without this the marker
        # was found and the caller was told it was not (2026-10-30).
        return 0
    }
    if await "$STARTED" && await "$PROMPT"; then
        local first=1 line tries
        for line in "$@" nosuchcommand; do
            printf '%s\r' "$line" >&3
            tries=0
            until grep -qF -- "$PROMPT$line" "$log" 2>/dev/null; do
                kill -0 "$qemu" 2>/dev/null || break
                ((tries += 1))
                ((tries > 40)) && break
                sleep 0.25
                # The first line is resent while unanswered, for the reason
                # `shell-test.sh` gives: the prompt is printed before the
                # shell is reading. Later lines queue and are never resent.
                if ((first)) && ((tries % 4 == 0)); then
                    printf '%s\r' "$line" >&3
                fi
            done
            first=0
        done
        await "nosuchcommand: not a command" || true
    fi
    exec 3>&-
    stop_machine
    rm -f "$fifo"
    # The serial line carries colour and carriage returns; the checks below
    # read text.
    sed -i 's/\x1b\[[0-9;]*m//g; s/\r//g' "$log"
}

check() {  # check LOG DESCRIPTION EXTENDED-REGEX
    if grep -qE -- "$3" "$1"; then pass "$2"; else fail "$2"; fi
}

echo "boot 1 of 4: a fresh disk carrying the project's marker, up to ${TIMEOUT}s..."
DISK="$WORK/domain.img"
make_marked_disk "$DISK"
boot_and_type "$DISK" "$WORK/boot1.log" "pkg install hello.bpk" "pkg list"
check "$WORK/boot1.log" "boot 1 formatted the marked disk and ran the journal's full self-test" \
    "disk journal +a filesystem on the virtio disk, through the block service"
check "$WORK/boot1.log" "boot 1 installed hello" "installed.*/pkg/hello"
check "$WORK/boot1.log" "boot 1 lists it" "(^|[^0-9])1 installed"

echo "boot 2 of 4: the same disk again, held to every gate boot-test.sh applies..."
if BHASKIX_DOMAIN_DISK_KEEP="$DISK" BHASKIX_LANE=disk-keeps "$REPO_ROOT/tests/qemu/boot-test.sh" iommu \
        > "$WORK/boot2.out" 2>&1; then
    pass "boot 2, on the kept disk, passed every gate boot-test.sh applies ($(sed 's/\x1b\[[0-9;]*m//g' "$WORK/boot2.out" | grep -c '^ok ') checks)"
else
    fail "boot 2, on the kept disk, failed boot-test.sh: $(sed 's/\x1b\[[0-9;]*m//g' "$WORK/boot2.out" | grep -m1 -E '^FAIL' | cut -c1-160)"
fi

echo "boot 3 of 4: the same disk a third time, typed at..."
boot_and_type "$DISK" "$WORK/boot3.log" "pkg list" "pkg run hello"
check "$WORK/boot3.log" "boot 3's block service read this system's filesystem in sector 0" \
    "block service +512 bytes of sector 0 through the service, and they begin this system's filesystem, kept from an earlier boot"
check "$WORK/boot3.log" "boot 3 kept the disk again" \
    "disk journal +kept: this disk already held this system's filesystem, so it was mounted and not formatted"
check "$WORK/boot3.log" "the package boot 1 installed is still installed, two reboots later" "(^|[^0-9])1 installed"
check "$WORK/boot3.log" "and it runs" "namaste from an installed package"

echo "boot 4 of 4: a disk that is not the project's..."
FOREIGN="$WORK/foreign.img"
printf 'FOREIGN-DOMAIN-DISK-NOT-OURS' > "$FOREIGN"
head -c 4194276 /dev/urandom >> "$FOREIGN"
before=$(sha256sum "$FOREIGN" | cut -d' ' -f1)
boot_and_type "$FOREIGN" "$WORK/boot4.log"
after=$(sha256sum "$FOREIGN" | cut -d' ' -f1)
check "$WORK/boot4.log" "boot 4's block service read the disk and called it not the project's" \
    "block service +512 bytes of sector 0 through the service: neither the domain disk's marker nor this system's filesystem"
check "$WORK/boot4.log" "boot 4 left the disk alone" \
    "disk journal +left alone: sector 0 holds neither the domain disk's marker nor this system's filesystem"
check "$WORK/boot4.log" "boot 4 started no filesystem service on it" "fs domain +not started: the disk was left alone"
if [[ "$before" == "$after" ]]; then
    pass "the foreign disk is byte for byte what it was: sha256 ${before:0:16}..."
else
    fail "the foreign disk changed: sha256 ${before:0:16}... became ${after:0:16}..."
fi

if ((status)) && [[ -n ${BHASKIX_KEEP_LOGS:-} ]]; then
    mkdir -p "$BHASKIX_KEEP_LOGS"
    cp "$WORK"/boot*.log "$WORK"/boot2.out "$BHASKIX_KEEP_LOGS"/
    echo "logs kept in $BHASKIX_KEEP_LOGS"
fi
exit "$status"
