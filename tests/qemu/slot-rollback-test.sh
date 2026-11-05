#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0100 step 2: a rollback counter in the TPM, and a signed older set
# refused.
#
# The native loader under OVMF with an emulated TPM 2.0 (`tools/swtpm.sh`),
# whose state is wiped once at the start and then kept from boot to boot, as a
# machine's TPM keeps it; and a slot disk from `tools/slot-disk.py` whose sets
# are signed with the published test key at chosen security versions. Each
# set's `boot.conf` names its slot and version, which the kernel prints, so a
# boot says which set actually ran.
#
#   1. A (version 1) active, a TPM never used  -> the counter created, at 1, locked
#   2. B (version 0) on trial                  -> B refused as older; A in the same boot
#   3. B (version 2) on trial                  -> B boots; the counter stays at 1
#   4. B (version 2) marked active             -> B boots; the counter moves to 2
#   5. A (version 1) marked active, B at 3     -> A refused as older; B in the same boot,
#                                                 and the counter not moved for B
#   6. no slot disk; a version-1 set on the ESP -> the ESP's set is held to the counter too
#   7. no slot disk, a TPM never used, twice   -> nothing created in it
#   8. no TPM, the slot disk                   -> said, in capitals, and A boots
#
# Every boot reads what the one before it wrote: the counter's value on boot
# N+1 is the TPM's answer, not the loader's memory.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
BOOTSIGN="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/bootsign"
TEST_KEY="$REPO_ROOT/tests/keys/bootsig-TEST-KEY"
SLOTS="$REPO_ROOT/tools/slot-disk.py"
TIMEOUT="${SLOT_BOOT_TIMEOUT:-90}"
TPM_DIR="$REPO_ROOT/build/swtpm-rollback"
WORK="$(mktemp -d)"
status=0

pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*"; status=1; }

for need in "$LOADER" "$KERNEL" "$INITRD" "$BOOTSIGN"; do
    [[ -f $need ]] || { echo "missing $need -- run make, make \$(BOOTEFI) and make bootsign" >&2; exit 1; }
done

# OVMF as a CODE/VARS pair, searched as native-boot-test.sh searches.
OVMF_CODE="" OVMF_VARS=""
for pair in "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd" \
    "/usr/share/qemu/OVMF_CODE.fd:/usr/share/qemu/OVMF_VARS.fd"; do
    code="${pair%%:*}" vars="${pair##*:}"
    if [[ -f $code && -f $vars ]]; then OVMF_CODE="$code" OVMF_VARS="$vars"; break; fi
done
if [[ -z $OVMF_CODE ]]; then
    printf '\033[1;33mskip\033[0m  slot rollback test (OVMF not installed)\n'
    exit 0
fi
# No container runtime, no emulator: said, as the TPM lanes say it.
if ! docker info >/dev/null 2>&1; then
    if [[ "${BHASKIX_REQUIRE:-0}" == 1 ]]; then
        fail "no usable docker for tools/swtpm.sh, and this run requires the rollback lane"
        exit 1
    fi
    printf '\033[1;33mskip\033[0m  slot rollback test (no usable docker for tools/swtpm.sh)\n'
    exit 0
fi
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"

qemu=""
stop_machine() {
    if [[ -n $qemu ]]; then
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
        qemu=""
    fi
}
stop_tpm() { "$REPO_ROOT/tools/swtpm.sh" stop "$TPM_DIR"; }
# A TPM never used: its state wiped. The emulator writes it as this user.
fresh_tpm() { stop_tpm; rm -rf "$TPM_DIR/state"; }
trap 'stop_machine; stop_tpm; rm -rf "$WORK"' EXIT

# Signed sets: a slot's letter and a security version each.
make_set() {  # make_set NAME SLOT VERSION
    local dir="$WORK/$1"
    mkdir -p "$dir/bhaskix"
    cp "$KERNEL" "$dir/bhaskix/kernel"
    cp "$INITRD" "$dir/bhaskix/initrd.tar"
    printf 'cmdline=bhaskix.slot=%s bhaskix.version=%s\n' "$2" "$3" > "$dir/bhaskix/boot.conf"
    "$BOOTSIGN" sign --key "$TEST_KEY.secret" --security-version "$3" "$dir" >/dev/null \
        || { echo "bootsign could not sign set $1" >&2; exit 1; }
}
make_set a1 a 1
make_set b0 b 0
make_set b2 b 2
make_set b3 b 3

ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp "$OVMF_VARS" "$WORK/vars.fd"

DISK="$WORK/slots.img"
make_disk() {  # make_disk SET-A SET-B
    python3 -I "$SLOTS" make "$DISK" --a "$WORK/$1/bhaskix" --b "$WORK/$2/bhaskix" >/dev/null
}
record() { python3 -I "$SLOTS" record "$DISK" "$@" >/dev/null; }

# Boots once, logging to $1. $2 may be "no-disk", "no-tpm" or empty.
boot() {
    local log="$1" disk=(-drive "if=ide,index=3,format=raw,file=$DISK")
    TPM_ARGS=()
    [[ ${2:-} == no-disk ]] && disk=()
    if [[ ${2:-} != no-tpm ]]; then
        "$REPO_ROOT/tools/swtpm.sh" start "$TPM_DIR" || { fail "the TPM emulator did not start"; exit 1; }
        qemu_tpm_args "$TPM_DIR/swtpm.sock" crb
    fi
    : > "$log"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35 -cpu max -smp 2 -m 256 -display none \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
        -drive "format=raw,file=fat:rw:$ESP" \
        "${disk[@]}" "${TPM_ARGS[@]}" \
        -serial "file:$log" >/dev/null 2>&1 &
    qemu=$!
    for _ in $(seq 1 $((TIMEOUT * 4))); do
        grep -aqE '^ +cmdline {4,}[^ ]|refusing to boot|bhaskixboot: .*REFUSED' "$log" 2>/dev/null && break
        kill -0 "$qemu" 2>/dev/null || break
        sleep 0.25
    done
    sleep 0.5
    stop_machine
    # The emulator is stopped between boots, as a machine's power is: its
    # state stays on disk, and a write lock does not.
    [[ ${2:-} == no-tpm ]] || stop_tpm
    sed -i 's/\x1b\[[0-9;]*m//g; s/\r//g' "$log"
}

# What the kernel says it was handed: its command line's slot and version.
booted() { grep -aoE '^ +cmdline {4,}bhaskix\.slot=[ab] bhaskix\.version=[0-9]+' "$1" | head -1 | sed -E 's/.*slot=([ab]) bhaskix\.version=([0-9]+)/\1\2/'; }
expect() {  # expect LOG DESCRIPTION SLOT+VERSION EXTENDED-REGEX...
    local log="$1" what="$2" want="$3" pattern ok=1
    shift 3
    [[ $(booted "$log") == "$want" ]] || ok=0
    for pattern in "$@"; do grep -aqE -- "$pattern" "$log" || ok=0; done
    if ((ok)); then
        pass "$what"
    else
        fail "$what: the kernel was handed '$(booted "$log")'; the loader said: $(grep -a 'bhaskixboot: \(slot\|booting\|rollback\|ROLLBACK\|NO ROLLBACK\|security\|boot signature\|the TPM\)' "$log" | tr '\n' '|' | cut -c1-600)"
    fi
}
absent() {  # absent LOG DESCRIPTION EXTENDED-REGEX
    if grep -aqE -- "$3" "$1"; then
        fail "$2: the loader said: $(grep -aE -- "$3" "$1" | head -1)"
    else
        pass "$2"
    fi
}

LOCKED='bhaskixboot: rollback counter: locked until the next restart, and a write was refused \(TPM_RC_NV_LOCKED\)'

echo "boot 1 of 9: slot A at version 1, a TPM never used..."
fresh_tpm
make_disk a1 b0
boot "$WORK/boot1.log"
expect "$WORK/boot1.log" "the counter was created in the TPM, moved to the version of the set marked good, and locked" a1 \
    'bhaskixboot: rollback counter: created in the TPM' \
    'bhaskixboot: security version 1; the rollback counter is at 0' \
    'bhaskixboot: rollback counter: advanced to 1, the version of the set marked good' \
    "$LOCKED" \
    "bhaskixboot: the TPM's owner has NO PASSWORD"

echo "boot 2 of 9: slot B at version 0 on trial..."
record --active a --trial b --tries 1
boot "$WORK/boot2.log"
expect "$WORK/boot2.log" "a signed set older than the counter was refused, and slot A booted in the same boot" a1 \
    'bhaskixboot: rollback counter: at 1; a set below that version is refused' \
    'bhaskixboot: boot signature NOT VERIFIED \(the set is signed, and older than the rollback counter allows\)' \
    'bhaskixboot: security version 0 is below the rollback counter.s 1: an older set, signed and refused' \
    "bhaskixboot: slot B's set did not verify; falling back to slot A" \
    "$LOCKED"

echo "boot 3 of 9: slot B at version 2 on trial..."
make_disk a1 b2
record --active a --trial b --tries 1
boot "$WORK/boot3.log"
expect "$WORK/boot3.log" "a newer set on trial booted, and the counter did not move for it" b2 \
    'bhaskixboot: booting slot B on trial' \
    'bhaskixboot: security version 2; the rollback counter is at 1' \
    "$LOCKED"
absent "$WORK/boot3.log" "a trial never advances the counter" 'rollback counter: advanced'

echo "boot 4 of 9: slot B marked active..."
record --active b
boot "$WORK/boot4.log"
expect "$WORK/boot4.log" "the set marked good booted, and the counter moved to its version" b2 \
    'bhaskixboot: rollback counter: at 1;' \
    'bhaskixboot: rollback counter: advanced to 2, the version of the set marked good' \
    "$LOCKED"

echo "boot 5 of 9: slot A, at version 1, marked active; slot B at version 3..."
# B newer than the counter and not marked good: booted as the fallback, it must
# not move the counter -- only the active slot's set does.
make_disk a1 b3
boot "$WORK/boot5.log"
expect "$WORK/boot5.log" "a genuinely signed older set was refused once the counter had passed it, and slot B booted" b3 \
    'bhaskixboot: rollback counter: at 2;' \
    'bhaskixboot: security version 1 is below the rollback counter.s 2: an older set, signed and refused' \
    "bhaskixboot: slot A's set did not verify; falling back to slot B"
absent "$WORK/boot5.log" "the counter moves for the active slot only" 'rollback counter: advanced'

echo "boot 6 of 9: no slot disk, a version-1 set on the ESP..."
mkdir -p "$ESP/bhaskix"
cp "$WORK/a1/bhaskix/"* "$ESP/bhaskix/"
boot "$WORK/boot6.log" no-disk
expect "$WORK/boot6.log" "without the slot disk the ESP's set was held to the counter too; Secure Boot off, it booted and said so" a1 \
    'bhaskixboot: rollback counter: at 2;' \
    'bhaskixboot: security version 1 is below the rollback counter.s 2' \
    'NOT ENFORCED: Secure Boot is off -- booting' \
    "$LOCKED"

echo "boots 7-8 of 9: no slot disk, a TPM never used..."
fresh_tpm
boot "$WORK/boot7.log" no-disk
boot "$WORK/boot8.log" no-disk
expect "$WORK/boot8.log" "with no slot disk nothing was created in the TPM: the second boot still found none" a1 \
    'bhaskixboot: rollback counter: none in this TPM; one is created on the first boot with a slot disk'
absent "$WORK/boot7.log" "and the first did not create one" 'rollback counter: created'

echo "boot 9 of 9: no TPM..."
make_disk a1 b2
boot "$WORK/boot9.log" no-tpm
expect "$WORK/boot9.log" "with a slot disk and no TPM the loader booted and said, in capitals, that nothing holds a set to a version" a1 \
    'bhaskixboot: NO ROLLBACK COUNTER: no TPM -- an older signed set would boot' \
    'bhaskixboot: security version 1; no rollback counter to hold it to'

if ((status)) && [[ -n ${BHASKIX_KEEP_LOGS:-} ]]; then
    mkdir -p "$BHASKIX_KEEP_LOGS"
    cp "$WORK"/boot*.log "$BHASKIX_KEEP_LOGS"/
    echo "logs kept in $BHASKIX_KEEP_LOGS"
fi
exit $status
