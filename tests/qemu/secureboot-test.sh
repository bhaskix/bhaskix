#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0091 step 5: **the native loader under Secure Boot**, both links at once.
#
# Link 1 is the firmware checking the loader's Authenticode signature against
# `db`. Here that is OVMF's Secure Boot build, with the distribution's
# **snakeoil** variable store: its test key is enrolled in PK, KEK and db, and
# its private half ships beside it on purpose. Link 2 is the loader checking
# `boot.sig` against the published test key it was built with. Three boots, one
# claim each:
#
#   1. an unsigned loader is refused by the firmware, and never says a word;
#   2. a signed loader with a signed boot set verifies it, "Secure Boot on", and
#      the kernel reports it, the test key named in red;
#   3. the same with one kernel byte changed after signing is refused, on the
#      screen and the wire, and handed back to the boot manager -- which then
#      reports the boot option failed, as it does an image it refused itself.
#
# Two firmware layouts are found. CI's runner has the 4 MiB pair
# (`OVMF_CODE_4M.secboot.fd`, `OVMF_VARS_4M.snakeoil.fd`). This build host has
# only the 2 MiB pair, whose certificate expired in 2019 and is accepted anyway
# (RFC 0091 step 0's measurement). Both run on q35 with SMM, the flash
# secured, and `ICH9-LPC.disable_s3`: without the last, the 2 MiB build under
# QEMU 4.2.1 never reached its boot manager (step 0).
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
BOOTSIGN="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/bootsign"
TEST_KEY="$REPO_ROOT/tests/keys/bootsig-TEST-KEY"
TEST_KEY_ID=a6c913d8a0e2476e
SNAKEOIL="/usr/share/ovmf/PkKek-1-snakeoil"
TIMEOUT=120

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'
pass() { printf '%sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$1"; }

# A lane that cannot run here says so -- unless a skip would be a lie: CI sets
# BHASKIX_REQUIRE=1, because a job that exists to run this and skips it is green
# while testing nothing.
cannot_run() {
    if [[ "${BHASKIX_REQUIRE:-0}" == 1 ]]; then
        fail "$1, and this run requires the Secure Boot lane"
        exit 1
    fi
    printf '%sskip%s  Secure Boot lane (%s)\n' "$YELLOW" "$RESET" "$1"
    exit 0
}

if [[ -f /usr/share/OVMF/OVMF_CODE_4M.secboot.fd && -f /usr/share/OVMF/OVMF_VARS_4M.snakeoil.fd ]]; then
    CODE=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
    VARS=/usr/share/OVMF/OVMF_VARS_4M.snakeoil.fd
elif [[ -f /usr/share/OVMF/OVMF_CODE.secboot.fd && -f /usr/share/OVMF/OVMF_VARS.snakeoil.fd ]]; then
    CODE=/usr/share/OVMF/OVMF_CODE.secboot.fd
    VARS=/usr/share/OVMF/OVMF_VARS.snakeoil.fd
else
    cannot_run "no OVMF Secure Boot build with a snakeoil variable store"
fi
[[ -f "$SNAKEOIL.key" && -f "$SNAKEOIL.pem" ]] || cannot_run "no snakeoil key at $SNAKEOIL.{key,pem}"
command -v sbsign >/dev/null 2>&1 || cannot_run "no sbsign (sbsigntool)"
command -v openssl >/dev/null 2>&1 || cannot_run "no openssl"
for built in "$LOADER" "$KERNEL" "$INITRD" "$BOOTSIGN"; do
    [[ -f "$built" ]] || { fail "$built is not built (make test-boot-secureboot builds it)"; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
status=0

# The loader, signed for link 1 with the firmware's own test key. The key is
# encrypted with a password the package documents ('snakeoil', in Ubuntu
# 20.04's README.Debian); 26.04's key opens with it too (RFC 0091 step 0).
openssl rsa -in "$SNAKEOIL.key" -passin pass:snakeoil -out "$WORK/snakeoil.key" 2>/dev/null \
    || { fail "the snakeoil key would not open"; exit 1; }
sbsign --key "$WORK/snakeoil.key" --cert "$SNAKEOIL.pem" --output "$WORK/signed.efi" "$LOADER" \
    >/dev/null 2>&1 || { fail "sbsign could not sign the loader"; exit 1; }

# An ESP: a loader, the payload, and boot.sig over it from the test key.
stage() {
    local esp="$1" loader="$2"
    mkdir -p "$esp/EFI/BOOT" "$esp/bhaskix"
    cp "$loader" "$esp/EFI/BOOT/BOOTX64.EFI"
    cp "$KERNEL" "$esp/bhaskix/kernel"
    cp "$INITRD" "$esp/bhaskix/initrd.tar"
    printf 'cmdline=\n' > "$esp/bhaskix/boot.conf"
    "$BOOTSIGN" sign --key "$TEST_KEY.secret" "$esp" >/dev/null \
        || { fail "bootsign could not sign $esp"; exit 1; }
}

said() { tr -d '\r' < "$1" | sed 's/\x1b\[[0-9;=]*[a-zA-Z]//g'; }
# The disk's boot option -- our ESP -- and never the firmware's own shell, which
# the 2 MiB build tries first and refuses with the same words.
DISK='Boot[0-9A-F]+ "UEFI QEMU HARDDISK'

# One boot of an ESP, its serial output to "$2", until "$3" appears or the time
# runs out -- and then, if "$4" is given, until "$4" appears *after* "$3", for
# up to twenty seconds more.
boot() {
    local esp="$1" log="$2" until="$3" after="${4:-}"
    cp "$VARS" "$WORK/vars.fd"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on \
        -global ICH9-LPC.disable_s3=1 -cpu max -smp 2 -m 512M -display none \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$CODE" \
        -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
        -drive "if=ide,index=2,format=raw,file=fat:rw:$esp" \
        -serial "file:$log" -no-reboot -net none \
        >/dev/null 2>&1 &
    local pid=$!
    for _ in $(seq 1 "$TIMEOUT"); do
        said "$log" 2>/dev/null | grep -qE "$until" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if [[ -n "$after" ]]; then
        for _ in $(seq 1 20); do
            said "$log" | awk -v u="$until" '$0 ~ u { p = 1 } p' | grep -qE "$after" && break
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}
echo "using firmware: $(basename "$CODE") + $(basename "$VARS"), up to ${TIMEOUT}s a boot"

# 1. An unsigned loader: link 1 refuses it before it runs.
stage "$WORK/unsigned" "$LOADER"
boot "$WORK/unsigned" "$WORK/unsigned.log" "failed to (load|start) $DISK.*(Security Violation|Access Denied)"
if said "$WORK/unsigned.log" | grep -qE "failed to (load|start) $DISK.*(Security Violation|Access Denied)" \
    && ! grep -qaF "the machine entered through our own door" "$WORK/unsigned.log"; then
    pass "the firmware refused the unsigned loader, which never said a word: $(said "$WORK/unsigned.log" | grep -E "failed to (load|start) $DISK" | grep -oE '(Security Violation|Access Denied)' | head -1)"
else
    fail "the unsigned loader was not refused by the firmware: $(said "$WORK/unsigned.log" | grep -aE 'BdsDxe|bhaskixboot' | tail -2 | tr '\n' ' ')"
    status=1
fi

# 2. A signed loader and a signed boot set: both links hold.
stage "$WORK/good" "$WORK/signed.efi"
boot "$WORK/good" "$WORK/good.log" "boot signature  (verified|NOT)"
good="$(said "$WORK/good.log")"
if grep -qF "bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader" <<< "$good"; then
    pass "the firmware verified the signed loader, and the loader read SecureBoot as 1"
else
    fail "the loader did not read SecureBoot as 1: $(grep -aE 'SecureBoot|BdsDxe: failed' <<< "$good" | head -2 | tr '\n' ' ')"
    status=1
fi
if grep -qF "bhaskixboot: boot signature verified: key $TEST_KEY_ID TEST KEY, Secure Boot on" <<< "$good"; then
    pass "the loader verified the boot set with Secure Boot on: key $TEST_KEY_ID, named as the test key"
else
    fail "the loader's verdict under Secure Boot: $(grep -aE 'bhaskixboot: boot signature' <<< "$good" | head -1)"
    status=1
fi
if grep -qF "boot signature  verified: key $TEST_KEY_ID TEST KEY, Secure Boot on -- the test key is published, so anyone could have signed this" <<< "$good"; then
    pass "the kernel reported it enforced, and in red, because the test key is published"
else
    fail "the kernel's boot signature line under Secure Boot: $(grep -aE '    boot signature' <<< "$good" | head -1)"
    status=1
fi

# 3. The same, with one kernel byte changed after signing: link 2 refuses it,
# and hands the machine back to the boot manager.
stage "$WORK/bent" "$WORK/signed.efi"
# The complement of whatever is there, so the kernel really differs: a fixed
# 0xff was a no-op on 2026-10-31, when that byte already held it.
"$REPO_ROOT/tools/flip-byte.sh" "$WORK/bent/bhaskix/kernel" 100000
# Until the loader hands back, and then the boot manager's answer about our disk,
# past the five seconds the refusal stays on the screen.
boot "$WORK/bent" "$WORK/bent.log" "returning to the boot manager" "failed to start $DISK"
bent="$(said "$WORK/bent.log")"
if grep -qF "bhaskixboot: refusing to boot: the kernel is not the one boot.sig names (Secure Boot is on)" <<< "$bent" \
    && grep -qF "bhaskixboot: returning to the boot manager in 5 seconds" <<< "$bent" \
    && ! grep -qF "jumping: entry" <<< "$bent"; then
    pass "a changed kernel was refused under Secure Boot, said on the wire, and nothing jumped"
else
    fail "the changed kernel under Secure Boot: $(grep -aE 'bhaskixboot: (boot signature|refusing|returning|the world is built)' <<< "$bent" | head -3 | tr '\n' ' ')"
    status=1
fi
after_return="$(awk '/returning to the boot manager/ { p = 1 } p' <<< "$bent")"
if grep -qE "failed to start $DISK" <<< "$after_return"; then
    pass "the boot manager took it back and called our disk's option failed: $(grep -E "failed to start $DISK" <<< "$after_return" | head -1 | sed -E 's/.*\): //' | cut -c1-70)"
else
    fail "the boot manager never reported the option failed after the loader returned"
    status=1
fi

exit "$status"
