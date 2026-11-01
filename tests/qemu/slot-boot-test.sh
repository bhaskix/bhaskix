#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0100 step 1: two slots, a record, and a loader that falls back.
#
# The native loader under OVMF, with an ESP holding nothing but the loader and
# a second disk built by `tools/slot-disk.py`: a slot record, and slots A and B,
# each a complete boot set signed with the published test key. Each set's
# `boot.conf` names its slot on the command line, which the kernel prints, so
# every boot below says which set actually ran, not only which one the loader
# meant to run.
#
#   1. A active                      -> A
#   2. B on trial, two boots         -> B, the record says one left
#   3.                               -> B, none left
#   4.                               -> A, the trial over and cleared
#   5. B on trial and damaged        -> B refused, A boots in the same boot
#   6. B active, the record damaged  -> A, and nothing written
#   7. no slot disk                  -> the set on the ESP, as before
#
# Every boot runs until the kernel prints its command line, and no further:
# what is asserted is the loader's choice and the kernel it handed over to.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
BOOTSIGN="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/bootsign"
TEST_KEY="$REPO_ROOT/tests/keys/bootsig-TEST-KEY"
SLOTS="$REPO_ROOT/tools/slot-disk.py"
TIMEOUT="${SLOT_BOOT_TIMEOUT:-90}"
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
    printf '\033[1;33mskip\033[0m  slot boot test (OVMF not installed)\n'
    exit 0
fi

qemu=""
stop_machine() {
    if [[ -n $qemu ]]; then
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
        qemu=""
    fi
}
trap 'stop_machine; rm -rf "$WORK"' EXIT

# Two signed sets, each naming its slot on the command line.
for slot in a b; do
    mkdir -p "$WORK/set-$slot/bhaskix"
    cp "$KERNEL" "$WORK/set-$slot/bhaskix/kernel"
    cp "$INITRD" "$WORK/set-$slot/bhaskix/initrd.tar"
    printf 'cmdline=bhaskix.slot=%s\n' "$slot" > "$WORK/set-$slot/bhaskix/boot.conf"
    "$BOOTSIGN" sign --key "$TEST_KEY.secret" "$WORK/set-$slot" >/dev/null \
        || { echo "bootsign could not sign set $slot" >&2; exit 1; }
done

# The ESP: the loader, and nothing for it to read -- so a boot that reaches the
# kernel read its set from a slot. The last scenario adds a set of its own.
ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp "$OVMF_VARS" "$WORK/vars.fd"

DISK="$WORK/slots.img"
make_disk() {
    python3 -I "$SLOTS" make "$DISK" --a "$WORK/set-a/bhaskix" --b "$WORK/set-b/bhaskix" >/dev/null
}

# Boots once, with the slot disk unless $2 is "no-disk", logging to $1, until
# the kernel prints its command line or the loader stops.
boot() {
    local log="$1" disk=()
    [[ ${2:-} == no-disk ]] || disk=(-drive "if=ide,index=3,format=raw,file=$DISK")
    : > "$log"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35 -cpu max -smp 2 -m 256 -display none \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
        -drive "format=raw,file=fat:rw:$ESP" \
        "${disk[@]}" \
        -serial "file:$log" >/dev/null 2>&1 &
    qemu=$!
    for _ in $(seq 1 $((TIMEOUT * 4))); do
        grep -aqE '^ +cmdline {4,}[^ ]|refusing to boot|bhaskixboot: .*REFUSED' "$log" 2>/dev/null && break
        kill -0 "$qemu" 2>/dev/null || break
        sleep 0.25
    done
    sleep 0.5
    stop_machine
    sed -i 's/\x1b\[[0-9;]*m//g; s/\r//g' "$log"
}

# The slot the kernel says it was handed: its command line's `bhaskix.slot=`.
booted() { grep -aoE '^ +cmdline {4,}bhaskix\.slot=[ab]' "$1" | head -1 | grep -oE '[ab]$'; }
record() { python3 -I "$SLOTS" show "$DISK"; }
expect() {  # expect LOG DESCRIPTION SLOT EXTENDED-REGEX...
    local log="$1" what="$2" slot="$3" pattern ok=1
    shift 3
    [[ $(booted "$log") == "$slot" ]] || ok=0
    for pattern in "$@"; do grep -aqE -- "$pattern" "$log" || ok=0; done
    if ((ok)); then
        pass "$what"
    else
        fail "$what: the kernel was handed slot '$(booted "$log")'; the loader said: $(grep -a 'bhaskixboot: \(slot\|booting\|the \)' "$log" | tr '\n' '|' | cut -c1-300)"
    fi
}

echo "boot 1 of 7: slot A active..."
make_disk
boot "$WORK/boot1.log"
expect "$WORK/boot1.log" "slot A active: the loader read slot A from the slot disk, verified it, and booted it" a \
    'bhaskixboot: slot record: A active, nothing on trial' \
    'bhaskixboot: booting slot A, the active slot' \
    'boot signature verified: key'

echo "boots 2-4 of 7: slot B on trial for two boots..."
python3 -I "$SLOTS" record "$DISK" --active a --trial b --tries 2 >/dev/null
boot "$WORK/boot2.log"
expect "$WORK/boot2.log" "slot B on trial booted, the boot recorded as spent before it was taken" b \
    'bhaskixboot: booting slot B on trial; 1 boot\(s\) left after this one' \
    'bhaskixboot: slot record written'
[[ $(record) == "record: A active, B on trial, 1 boot(s) left, 2 write(s)" ]] \
    && pass "the record on the disk says one boot left: $(record)" \
    || fail "the record after the first trial boot: $(record)"
boot "$WORK/boot3.log"
expect "$WORK/boot3.log" "slot B on trial booted a second time, its last" b \
    'bhaskixboot: booting slot B on trial; 0 boot\(s\) left after this one'
boot "$WORK/boot4.log"
expect "$WORK/boot4.log" "with no boots left the trial is over: slot A booted, and the record cleared it" a \
    'bhaskixboot: the trial of slot B is over; booting slot A, the active slot' \
    'bhaskixboot: slot record written'
[[ $(record) == "record: A active, nothing on trial, 4 write(s)" ]] \
    && pass "the record on the disk says so: $(record)" \
    || fail "the record after the trial ended: $(record)"

echo "boot 5 of 7: slot B on trial, its kernel damaged..."
python3 -I "$SLOTS" record "$DISK" --active a --trial b --tries 2 >/dev/null
python3 -I "$SLOTS" damage "$DISK" b >/dev/null
boot "$WORK/boot5.log"
expect "$WORK/boot5.log" "a damaged slot B was refused and slot A booted in the same boot" a \
    'bhaskixboot: booting slot B on trial' \
    'boot signature NOT VERIFIED \(the kernel is not the one boot.sig names\), NOT ENFORCED: Secure Boot is off -- not booted: the other slot is tried' \
    "bhaskixboot: slot B's set did not verify; falling back to slot A" \
    'boot signature verified: key'

echo "boot 6 of 7: slot B active, the record damaged..."
make_disk
python3 -I "$SLOTS" record "$DISK" --active b >/dev/null
python3 -I "$SLOTS" damage "$DISK" record >/dev/null
before=$(sha256sum "$DISK" | cut -d' ' -f1)
boot "$WORK/boot6.log"
after=$(sha256sum "$DISK" | cut -d' ' -f1)
expect "$WORK/boot6.log" "a damaged record was not believed: slot A, not the B it named" a \
    'bhaskixboot: slot record damaged or unreadable: trying A, then B, and writing nothing'
[[ $before == "$after" ]] \
    && pass "and nothing was written: the disk's sha256 is unchanged" \
    || fail "the loader wrote to the disk although the record was damaged"

echo "boot 7 of 7: no slot disk..."
mkdir -p "$ESP/bhaskix"
cp "$WORK/set-a/bhaskix/"* "$ESP/bhaskix/"
printf 'cmdline=bhaskix.slot=a\n' > "$ESP/bhaskix/boot.conf"
"$BOOTSIGN" sign --key "$TEST_KEY.secret" "$ESP" >/dev/null
boot "$WORK/boot7.log" no-disk
if grep -aq 'bhaskixboot: slot disk:' "$WORK/boot7.log"; then
    fail "the loader found a slot disk where there was none"
else
    expect "$WORK/boot7.log" "with no slot disk the set was read from the ESP, as before" a \
        'bhaskixboot: reading bhaskix\\kernel' 'boot signature verified: key'
fi

if ((status)) && [[ -n ${BHASKIX_KEEP_LOGS:-} ]]; then
    mkdir -p "$BHASKIX_KEEP_LOGS"
    cp "$WORK"/boot*.log "$BHASKIX_KEEP_LOGS"/
    echo "logs kept in $BHASKIX_KEEP_LOGS"
fi
exit $status
