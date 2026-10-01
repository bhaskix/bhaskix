#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The motivating workload -- RFC 0086 step 5, and RFC 0005 step 10's gate.
#
# A static Go `net/http` server (`corpus/httpd`, built with the pinned Go) runs
# in a Linux-tagged domain, and sixteen keep-alive clients on the host load it
# through QEMU's port forward for the time asked, every body checked.
#
# **Passes when**, for the whole run: the load tool saw no error and every
# client was served; the kernel says the server was still running when its time
# was up; during its run no park was refused, none ran out of retries, and no
# deadline arm was refused for want of a slot; the adapter recorded its copies
# (RFC 0086's per-run copy cost -- present, not judged); and nothing printed
# `FAILED`. Throughput, latency and the copy cost per response are printed, not
# judged.
#
#   tests/qemu/http-test.sh [seconds]      (default 30; the nightly soak runs 300)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SECONDS_OF_LOAD="${1:-30}"
# Boot, the other self-tests, the load, and the kernel's thirty seconds after.
TIMEOUT="${HTTP_TEST_TIMEOUT:-$((SECONDS_OF_LOAD + 420))}"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; RESET=$'\033[0m'
status=0
pass() { printf '  %sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() {
    printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$1" >&2
    printf '::error::http-test: %s\n' "$1"
    status=1
}

# **Its own ramdisk and its own image**, under names no other lane uses: the
# server is 5.8 MB and the shared `build/initrd.tar` must never carry it. No
# `bhaskix.clients`, on purpose -- the stream and `epoll` probes would take two
# of `bin/tcpd`'s four listeners and two of the adapter's seventeen ring pairs
# for the rest of the boot, and the server needs sixteen connections.
INITRD="$REPO_ROOT/build/initrd-http.tar"
ISO="$REPO_ROOT/build/iso-http.iso"
echo "building an image with bin/httpd that serves for ${SECONDS_OF_LOAD}s..."
if ! make -C "$REPO_ROOT" iso HTTPD_IN_IMAGE=1 CMDLINE="bhaskix.httpd=$SECONDS_OF_LOAD" \
    INITRD="$INITRD" INITRD_ROOT="$REPO_ROOT/build/initrd_root_http" \
    ISO="$ISO" ISO_ROOT="$REPO_ROOT/build/iso_root_http" >/dev/null 2>&1; then
    fail "could not build the image (is the pinned Go reachable? tools/fetch-go.sh)"
    exit 1
fi

# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
source "$REPO_ROOT/tests/qemu/readings.sh"
# Translated, because the network is: without a unit the NIC has no window.
qemu_device_list full yes

LOG="${BHASKIX_HTTP_LOG:-$(mktemp)}"
: > "$LOG"
# Both disks fresh, as `boot-test.sh` makes them: the boot *writes* the domain
# disk, so one left from an earlier run fails the block service's check for a
# reason that has nothing to do with this lane -- which is how the first run of
# this script found it.
rm -f "$REPO_ROOT/build/sata-disk.img" "$REPO_ROOT/build/domain-disk.img"
make -C "$REPO_ROOT" build/sata-disk.img build/domain-disk.img >/dev/null 2>&1 || true

echo "booting, up to ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 \
    -M "$MACHINE" -cpu "${QEMU_CPU:-max}" -smp "${QEMU_SMP:-4}" -m 256M \
    "${IOMMU_ARGS[@]}" \
    -drive "file=$INITRD,format=raw,if=none,id=disk0,readonly=on" \
    -drive "file=$REPO_ROOT/build/domain-disk.img,format=raw,if=none,id=disk1" \
    "${VIRTIO_ARGS[@]}" \
    -no-reboot -cdrom "$ISO" -boot d -serial "file:$LOG" -display none >/dev/null 2>&1 &
qemu=$!

await() {
    local pattern="$1" limit="$2" waited=0
    while ! grep -aqE -- "$pattern" "$LOG" 2>/dev/null; do
        kill -0 "$qemu" 2>/dev/null || return 1
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((limit * 4)) ]] && return 1
    done
    return 0
}

load_status=1
if await "httpd listening|httpd +(FAILED|skipped)" "$TIMEOUT" \
    && grep -aqF "httpd listening" "$LOG"; then
    pass "the server listens: its own 'httpd listening', from inside the domain"
    "$REPO_ROOT/tools/http-load.py" --port "$BHASKIX_HTTP_PORT" \
        --seconds "$SECONDS_OF_LOAD" --clients 16 | tee "$LOG.load"
    load_status=${PIPESTATUS[0]}
else
    fail "the server never said it was listening: $(grep -aoE 'httpd +[^\r]*' "$LOG" | tail -1 | sed 's/\x1b\[[0-9;]*m//g')"
fi

await "Nothing left to do at this milestone|KERNEL PANIC" $((SECONDS_OF_LOAD + 120)) || true
kill -0 "$qemu" 2>/dev/null && kill "$qemu" 2>/dev/null
wait "$qemu" 2>/dev/null

clean() { sed 's/\x1b\[[0-9;]*m//g'; }

if [[ $load_status -eq 0 ]]; then
    pass "16 keep-alive clients for ${SECONDS_OF_LOAD}s, every body checked: $(sed -n 's/^http load  //p' "$LOG.load" | head -1)"
elif [[ -f "$LOG.load" ]]; then
    fail "the load failed: $(sed -n 's/^http load  //p' "$LOG.load" | tr '\n' ' ')"
fi

serving="$(grep -aE "httpd +still serving after" "$LOG" | clean | sed 's/^ *//')"
if [[ -n "$serving" ]]; then
    pass "$serving"
else
    fail "the kernel never said the server was still serving: $(grep -aE 'httpd +' "$LOG" | clean | tail -2 | tr '\n' ' ')"
fi

run="$(grep -aE "httpd +during its run:" "$LOG" | clean | sed 's/^ *//')"
if [[ "$run" =~ during\ its\ run:\ 0\ park\(s\)\ refused,\ 0\ ran\ out\ of\ retries,\ 0\ unarmed,\ 0\ ungranted,\ 0\ unnamed\;\ 0\ deadline ]]; then
    pass "$run"
else
    fail "the server was refused a park or a deadline during its run: ${run:-no park line was printed}"
fi

# **The adapter's copy cost per response** -- RFC 0086's "reported, not
# gated". The kernel prints the run's totals and only the host knows how many
# responses there were, so the division is here. The figure is not judged; its
# *presence* is: a run that served responses and recorded no crossing has an
# instrument that is not counting, and a number nobody can trust is worse than
# none.
copies="$(grep -aoE 'copies during its run: .*' "$LOG" | head -1 | clean)"
responses="$(sed -n 's/^http load  \([0-9]*\) responses checked.*/\1/p' "$LOG.load" 2>/dev/null | head -1)"
if [[ "$copies" =~ run:\ ([0-9]+)\ in\ \(([0-9]+)\ bytes,\ ([0-9]+)\ cycles\),\ ([0-9]+)\ out\ \(([0-9]+)\ bytes,\ ([0-9]+)\ cycles\)\;\ ([0-9]+)\ cycles\ per ]] \
    && [[ ${responses:-0} -gt 0 ]]; then
    m=("${BASH_REMATCH[@]}")
    if [[ $((m[1] + m[4])) -gt 0 ]]; then
        pass "$copies"
        echo "  info  per response: $(awk -v r="$responses" -v ci="${m[1]}" -v bi="${m[2]}" \
            -v yi="${m[3]}" -v co="${m[4]}" -v bo="${m[5]}" -v yo="${m[6]}" 'BEGIN {
            printf "%.2f crossings in and %.2f out, %.0f bytes in and %.0f out, %.0f cycles copying",
                ci / r, co / r, bi / r, bo / r, (yi + yo) / r }')"
    else
        fail "the server answered $responses responses and the adapter recorded no copy: $copies"
    fi
elif [[ ${responses:-0} -gt 0 ]]; then
    fail "the server answered $responses responses and the kernel printed no copy totals: ${copies:-no line}"
fi

# **Which calls make those crossings**: the server's most-asked call numbers,
# per response. Printed, not judged; the kernel counts numbers and names none.
most="$(grep -aoE "most-asked calls, number x count:.*" "$LOG" | head -1 | clean | sed 's/.*count://')"
if [[ -n "$most" && ${responses:-0} -gt 0 ]]; then
    echo "  info  most-asked calls per response (number: count):$(for pair in $most; do
        awk -v n="${pair%x*}" -v c="${pair#*x}" -v r="$responses" 'BEGIN { printf " %s: %.2f", n, c / r }'
    done)"
fi

# What `MADV_DONTNEED` did during the run, printed and not judged: a short run
# may release nothing, which is no failure. Whether the kernel serves a discard
# at all is asserted on every boot of every lane, by the memory probe's own
# discard-and-read-zero (`MEMORY_CODE`), since a whitelist that left it out
# made every Go run past a minute corrupt its heap (2026-10-01).
echo "  info  $(grep -aoE 'MADV_DONTNEED this boot: .*' "$LOG" | head -1 | clean)"

for marker in "KERNEL PANIC" "EXCEPTION" "FAILED"; do
    if grep -aqF -- "$marker" "$LOG"; then
        fail "found failure marker: $marker -- $(grep -am1 -F -- "$marker" "$LOG" | clean | cut -c1-200)"
    fi
done

echo
print_readings "$LOG"
rm -f "$LOG.load"
if [[ $status -ne 0 ]]; then
    echo "--- the serial log of this failing run is kept at $LOG ---"
fi
exit $status
