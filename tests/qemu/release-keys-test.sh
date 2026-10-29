#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RFC 0091 step 6, rehearsed: **the key ceremony, end to end, with throwaway
# keys**, and the boots that show its two decisions hold -- an offline CA in
# `db` with a signing leaf beneath it (question 5), and `dbx` for loss
# (question 6).
#
# The ceremony is tools/release-keys.sh --rehearsal: init, export, backup and
# restore, sign, rotate-leaf -- the commands the lead will type, in the
# environment they will type them in (Ubuntu 26.04: natively on CI's runner, in
# a pinned container here, whose 20.04 has neither OpenSSL 3 nor the
# variable-store editor). Then a loader built with the rehearsal's boot-set key,
# five boots under OVMF's Secure Boot build with the rehearsal CA enrolled:
#
#   (a) signed by the leaf, a signed boot set: verified, Secure Boot on;
#   (b) signed by a second leaf, after rotate-leaf -- nothing re-enrolled: boots;
#   (c) the first leaf's certificate in dbx: refused (UEFI 2.10 s32.6.3.3, item C);
#   (d) the loader's Authenticode hash in dbx: refused (item A);
#   (e) signed by a key the CA never certified: refused.
#
# And the recipe's check on what comes back: tools/release-finish.sh accepts
# the rehearsal's signed loader and boot.sig, and refuses a leaf-signed loader
# that is not the one built, and a boot.sig made with another key.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
BOOTSIGN="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/bootsign"
KEYS_TOOL="$REPO_ROOT/tools/release-keys.sh"
LOADER_DIR="$REPO_ROOT/build/rehearsal-loader"
TIMEOUT=120
# The owner's GUID in the variable store: any fixed one; the firmware does not
# care whose it is.
OWNER=5b1a4c2e-9d3f-4e6a-8b7c-1f2e3d4c5b6a

# The rehearsal environment's pins -- read from a 26.04 container on 2026-10-29
# (RFC 0091 step 0), not guessed. When the archive stops carrying one, the
# build fails loudly here; re-pin then, on purpose.
BASE="ubuntu@sha256:0e73b71479e7bc5f006bca872e25c3cd680dc052a0116f90d63ae363537db0dd"
OPENSSL_VERSION=3.5.5-1ubuntu3.7
SBSIGNTOOL_VERSION=0.9.4-3.1ubuntu9
VIRT_FIRMWARE_VERSION=25.12-1
PESIGN_VERSION=116-8.1build1
IMAGE="bhaskix-rehearse:${SBSIGNTOOL_VERSION}-${VIRT_FIRMWARE_VERSION}"

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'
pass() { printf '%sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$1"; status=1; }
status=0

cannot_run() {
    if [[ "${BHASKIX_REQUIRE:-0}" == 1 ]]; then
        printf '%sFAIL%s  %s, and this run requires the rehearsal lane\n' "$RED" "$RESET" "$1"
        exit 1
    fi
    printf '%sskip%s  release-key rehearsal (%s)\n' "$YELLOW" "$RESET" "$1"
    exit 0
}

# --- where the ceremony runs ---------------------------------------------

native=0
if command -v virt-fw-vars >/dev/null && command -v pesign >/dev/null &&
    command -v sbsign >/dev/null && openssl version 2>/dev/null | grep -qE '^OpenSSL [3-9]'; then
    native=1
elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    docker image inspect "$IMAGE" >/dev/null 2>&1 ||
        docker build -q -t "$IMAGE" --build-arg BASE="$BASE" \
            --build-arg OPENSSL_VERSION="$OPENSSL_VERSION" \
            --build-arg SBSIGNTOOL_VERSION="$SBSIGNTOOL_VERSION" \
            --build-arg VIRT_FIRMWARE_VERSION="$VIRT_FIRMWARE_VERSION" \
            --build-arg PESIGN_VERSION="$PESIGN_VERSION" \
            "$REPO_ROOT/tools/rehearse" >/dev/null ||
        cannot_run "could not build $IMAGE"
else
    cannot_run "no 26.04 tools here (virt-fw-vars, pesign, sbsign, OpenSSL 3) and no Docker to bring them"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A command in the ceremony's environment: here, or in the pinned 26.04
# container with no network at all -- which is what the offline machine has.
# Paths are the same inside and out, so the commands do not change.
in_ceremony() {
    if (( native )); then
        "$@"
    else
        docker run --rm --network none --user "$(id -u):$(id -g)" \
            -v "$REPO_ROOT:$REPO_ROOT" -v "$WORK:$WORK" -w "$WORK" \
            -e BHASKIX_RELEASE_KEYS -e BHASKIX_BACKUP_PASS -e BOOTSIGN -e HOME="$WORK" \
            "$IMAGE" "$@"
    fi
}

# --- the firmware ----------------------------------------------------------

if [[ -f /usr/share/OVMF/OVMF_CODE_4M.secboot.fd && -f /usr/share/OVMF/OVMF_VARS_4M.fd ]]; then
    CODE=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
    PLAIN_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
elif [[ -f /usr/share/OVMF/OVMF_CODE.secboot.fd && -f /usr/share/OVMF/OVMF_VARS.fd ]]; then
    CODE=/usr/share/OVMF/OVMF_CODE.secboot.fd
    PLAIN_VARS=/usr/share/OVMF/OVMF_VARS.fd
else
    cannot_run "no OVMF Secure Boot build"
fi
for built in "$KERNEL" "$INITRD" "$BOOTSIGN"; do
    [[ -f "$built" ]] || { fail "$built is not built (make test-release-keys builds it)"; exit 1; }
done
cp "$PLAIN_VARS" "$WORK/plain-vars.fd"
echo "ceremony: $( (( native )) && echo "on this machine" || echo "in $IMAGE, no network" ); firmware: $(basename "$CODE")"

export BHASKIX_RELEASE_KEYS="$WORK/keys" BHASKIX_BACKUP_PASS="rehearsal-only" BOOTSIGN

# --- the ceremony ----------------------------------------------------------

# It refuses to run online. Asked here, outside any container, where this
# machine's network is up -- the one refusal --rehearsal does not lift.
if out="$(BHASKIX_RELEASE_KEYS="$WORK/online" "$KEYS_TOOL" init 2>&1)"; then
    fail "the ceremony ran with a network interface up"
elif grep -q "a network interface is not down" <<< "$out" && [[ ! -e "$WORK/online" ]]; then
    pass "the ceremony refuses to run with a network interface up, and made nothing"
else
    fail "the online refusal said something else: $(tail -1 <<< "$out")"
fi

if in_ceremony "$KEYS_TOOL" --rehearsal init > "$WORK/init.log" 2>&1 \
    && in_ceremony "$KEYS_TOOL" --rehearsal export "$WORK/public" > "$WORK/export.log" 2>&1; then
    pass "init and export: a CA, a leaf and a boot-set key; public halves only in the export"
else
    fail "init or export failed: $(tail -2 "$WORK/init.log" "$WORK/export.log" 2>/dev/null | tr '\n' ' ')"
    exit 1
fi
mkdir -p "$WORK/media"
if in_ceremony "$KEYS_TOOL" --rehearsal backup "$WORK/media" > "$WORK/backup.log" 2>&1 \
    && BHASKIX_RELEASE_KEYS="$WORK/restored" in_ceremony "$KEYS_TOOL" --rehearsal restore "$(ls "$WORK"/media/*.tar.enc)" > "$WORK/restore.log" 2>&1 \
    && diff -r "$WORK/keys" "$WORK/restored" >/dev/null; then
    pass "an encrypted backup, restored into an empty directory, byte for byte the keys"
else
    fail "backup and restore did not round-trip: $(tail -1 "$WORK/backup.log" "$WORK/restore.log" 2>/dev/null | tr '\n' ' ')"
fi
release_key="$(ls "$WORK"/public/bootsig-release-*.public)"
key_id="$(basename "$release_key" .public)"
key_id="${key_id#bootsig-release-}"

# The loader with the rehearsal's key compiled in, built apart from the lanes'
# as the release's is.
(cd "$REPO_ROOT/boot/bhaskixboot" && BHASKIX_BOOT_KEYS="$release_key" CARGO_TARGET_DIR="$LOADER_DIR" \
    cargo build --release --target x86_64-unknown-uefi --quiet) > "$WORK/build.log" 2>&1 ||
    { fail "the rehearsal loader did not build: $(tail -3 "$WORK/build.log" | tr '\n' ' ')"; exit 1; }
LOADER="$LOADER_DIR/x86_64-unknown-uefi/release/bhaskixboot.efi"

# The bundle make release-dist writes, from this build's kernel and initrd.
bundle="$WORK/to-sign"
mkdir -p "$bundle/bhaskix"
cp "$LOADER" "$bundle/bhaskixboot.efi"
cp "$KERNEL" "$bundle/bhaskix/kernel"
cp "$INITRD" "$bundle/bhaskix/initrd.tar"
printf 'cmdline=\n' > "$bundle/bhaskix/boot.conf"
(cd "$bundle" && sha256sum bhaskixboot.efi bhaskix/kernel bhaskix/initrd.tar bhaskix/boot.conf > SHA256SUMS)

if in_ceremony "$KEYS_TOOL" --rehearsal sign "$bundle" "$WORK/signed-1" > "$WORK/sign1.log" 2>&1; then
    pass "sign: the loader by the leaf, boot.sig over the boot set -- each verified before it stopped"
else
    fail "sign failed: $(tail -2 "$WORK/sign1.log" | tr '\n' ' ')"
    exit 1
fi
cp -r "$WORK/keys" "$WORK/keys-leaf-1"
in_ceremony "$KEYS_TOOL" --rehearsal rotate-leaf > "$WORK/rotate.log" 2>&1 &&
    in_ceremony "$KEYS_TOOL" --rehearsal sign "$bundle" "$WORK/signed-2" > "$WORK/sign2.log" 2>&1 ||
    fail "rotate-leaf and a second sign failed: $(tail -2 "$WORK/rotate.log" "$WORK/sign2.log" | tr '\n' ' ')"

# A signer the CA never certified, for (e).
in_ceremony openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=nobody the CA knows" \
    -keyout "$WORK/stranger.key" -out "$WORK/stranger.pem" >/dev/null 2>&1
in_ceremony sbsign --key "$WORK/stranger.key" --cert "$WORK/stranger.pem" \
    --output "$WORK/stranger.efi" "$LOADER" >/dev/null 2>&1
# The owner's platform key, which enrols the CA -- the owner's, not the project's.
in_ceremony openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=rehearsal owner" \
    -keyout "$WORK/owner.key" -out "$WORK/owner.pem" >/dev/null 2>&1

# --- the variable stores -----------------------------------------------------

enrol() {
    local out="$1"
    shift
    in_ceremony virt-fw-vars --input "$WORK/plain-vars.fd" --output "$out" \
        --set-pk "$OWNER" "$WORK/owner.pem" --add-kek "$OWNER" "$WORK/owner.pem" \
        --add-db "$OWNER" "$WORK/public/db-ca.pem" --no-microsoft --sb "$@" > /dev/null 2>&1
}
hash_2="$(in_ceremony pesign -h -i "$WORK/signed-2/bhaskixboot.efi" 2>/dev/null | awk '{ print $1 }')"
enrol "$WORK/vars-ca.fd" &&
    enrol "$WORK/vars-dbx-leaf.fd" --add-dbx-cert "$OWNER" "$WORK/keys-leaf-1/leaf.pem" &&
    enrol "$WORK/vars-dbx-hash.fd" --add-dbx-hash "$OWNER" "$hash_2" &&
    [[ ${#hash_2} -eq 64 ]] ||
    { fail "could not write the variable stores (the loader's hash read '$hash_2')"; exit 1; }

# --- the boots ---------------------------------------------------------------

said() { tr -d '\r' < "$1" | sed 's/\x1b\[[0-9;=]*[a-zA-Z]//g'; }
DISK='Boot[0-9A-F]+ "UEFI QEMU HARDDISK'
REFUSED="failed to (load|start) $DISK.*(Security Violation|Access Denied)"

# An ESP holding loader $1 and the rehearsal's signed boot set, booted on store
# $2, its serial output to $3, until $4 appears or the time runs out.
boot() {
    local loader="$1" vars="$2" log="$3" until="$4" esp
    esp="$WORK/esp-$(basename "$log" .log)"
    mkdir -p "$esp/EFI/BOOT"
    cp "$loader" "$esp/EFI/BOOT/BOOTX64.EFI"
    cp -r "$bundle/bhaskix" "$esp/bhaskix"
    cp "$WORK/signed-1/boot.sig" "$esp/bhaskix/boot.sig"
    cp "$vars" "$WORK/run-vars.fd"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on \
        -global ICH9-LPC.disable_s3=1 -cpu max -smp 2 -m 512M -display none \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$CODE" \
        -drive "if=pflash,unit=1,format=raw,file=$WORK/run-vars.fd" \
        -drive "if=ide,index=2,format=raw,file=fat:rw:$esp" \
        -serial "file:$log" -no-reboot -net none \
        >/dev/null 2>&1 &
    local pid=$!
    for _ in $(seq 1 "$TIMEOUT"); do
        said "$log" 2>/dev/null | grep -qE "$until" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}

# (a)
boot "$WORK/signed-1/bhaskixboot.efi" "$WORK/vars-ca.fd" "$WORK/a.log" "    boot signature  (verified|NOT)"
a="$(said "$WORK/a.log")"
if grep -qF "bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader" <<< "$a" \
    && grep -qF "bhaskixboot: boot signature verified: key $key_id, Secure Boot on" <<< "$a" \
    && grep -qxF "    boot signature  verified: key $key_id, Secure Boot on" <<< "$a"; then
    pass "(a) the leaf's loader booted on a store holding only the CA, and verified its boot set: key $key_id, Secure Boot on"
else
    fail "(a) the leaf-signed loader on the CA's store: $(grep -aE 'SecureBoot|boot signature|BdsDxe: failed' <<< "$a" | head -3 | tr '\n' ' ')"
fi

# (b)
boot "$WORK/signed-2/bhaskixboot.efi" "$WORK/vars-ca.fd" "$WORK/b.log" "boot signature verified|$REFUSED"
if said "$WORK/b.log" | grep -qF "bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader"; then
    pass "(b) a loader signed by the rotated leaf booted on the same store -- nothing re-enrolled"
else
    fail "(b) the rotated leaf's loader was not accepted: $(said "$WORK/b.log" | grep -aE 'BdsDxe|bhaskixboot' | tail -2 | tr '\n' ' ')"
fi

# (c), (d), (e): refused by the firmware, before the loader says a word --
# and, on each store with a `dbx` entry, **a control that the store still takes
# a loader the entry does not name**. Without it a refusal proves nothing: a
# store that had lost the CA altogether refuses everything, and the first armed
# run of this lane showed exactly that, passing (c) and (d) with no `dbx`
# entry at all (2026-10-29).
accepted() {
    local loader="$1" vars="$2" log="$3"
    boot "$loader" "$vars" "$log" "SecureBoot reads|$REFUSED"
    said "$log" | grep -qF "bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader"
}
refused() {
    local label="$1" loader="$2" vars="$3" log="$4" control="${5:-}" because="${6:-}"
    boot "$loader" "$vars" "$log" "$REFUSED|bhaskixboot:"
    if ! said "$log" | grep -qE "$REFUSED" || grep -qaF "bhaskixboot:" "$log"; then
        fail "$label was not refused: $(said "$log" | grep -aE 'BdsDxe|bhaskixboot' | head -2 | tr '\n' ' ')"
    elif [[ -n "$control" ]] && ! accepted "$control" "$vars" "${log%.log}-control.log"; then
        fail "$label -- but the same store also refused $because, so the refusal is not the entry's"
    else
        pass "$label: $(said "$log" | grep -oE '(Security Violation|Access Denied)' | head -1)${control:+, while the same store booted $because}"
    fi
}
# The control for (d): the lanes' own loader -- another binary, so another
# hash -- signed by the rotated leaf.
in_ceremony sbsign --key "$WORK/keys/leaf.key" --cert "$WORK/keys/leaf.pem" \
    --output "$WORK/other-2.efi" "$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi" >/dev/null 2>&1
refused "(c) the first leaf's certificate in dbx refused the loader it signed" \
    "$WORK/signed-1/bhaskixboot.efi" "$WORK/vars-dbx-leaf.fd" "$WORK/c.log" \
    "$WORK/signed-2/bhaskixboot.efi" "the rotated leaf's"
refused "(d) the loader's own hash in dbx refused it, though its leaf is good" \
    "$WORK/signed-2/bhaskixboot.efi" "$WORK/vars-dbx-hash.fd" "$WORK/d.log" \
    "$WORK/other-2.efi" "another loader the same leaf signed"
refused "(e) a loader signed by a key the CA never certified was refused" \
    "$WORK/stranger.efi" "$WORK/vars-ca.fd" "$WORK/e.log" \
    "$WORK/signed-2/bhaskixboot.efi" "the leaf's"

# --- the recipe's check on what comes back -------------------------------------

finish() {
    local signed="$1" dist="$WORK/dist-$(basename "$1")"
    rm -rf "$dist"
    mkdir -p "$dist"
    cp -r "$bundle" "$dist/to-sign"
    cp "$bundle/bhaskixboot.efi" "$dist/bhaskixboot.efi"
    printf 'stands in for the ISO\n' > "$dist/bhaskix.iso"
    BOOTSIGN="$BOOTSIGN" "$REPO_ROOT/tools/release-finish.sh" "$dist" "$signed" "$WORK/public" > "$WORK/finish.log" 2>&1
}
if finish "$WORK/signed-1"; then
    pass "release-finish accepted the rehearsal's signed loader and boot.sig against its public halves"
else
    fail "release-finish refused the rehearsal's own output: $(tail -1 "$WORK/finish.log")"
fi
# A loader the leaf signed that is not the one built: the lanes' own.
mkdir -p "$WORK/forged"
in_ceremony sbsign --key "$WORK/keys/leaf.key" --cert "$WORK/keys/leaf.pem" \
    --output "$WORK/forged/bhaskixboot.efi" "$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi" >/dev/null 2>&1
cp "$WORK/signed-1/boot.sig" "$WORK/forged/boot.sig"
(cd "$WORK/forged" && sha256sum bhaskixboot.efi boot.sig > SHA256SUMS)
if finish "$WORK/forged"; then
    fail "release-finish accepted a leaf-signed loader that is not the one built"
elif grep -q "is not the loader built here" "$WORK/finish.log"; then
    pass "release-finish refused a leaf-signed loader that is not the one built here"
else
    fail "release-finish refused the other loader for another reason: $(tail -1 "$WORK/finish.log")"
fi
# A boot.sig made with a key other than the release's: the published test key.
mkdir -p "$WORK/wrong-sig/esp/bhaskix"
cp "$WORK/signed-1/bhaskixboot.efi" "$WORK/wrong-sig/"
cp "$bundle"/bhaskix/* "$WORK/wrong-sig/esp/bhaskix/"
"$BOOTSIGN" sign --key "$REPO_ROOT/tests/keys/bootsig-TEST-KEY.secret" "$WORK/wrong-sig/esp" >/dev/null
cp "$WORK/wrong-sig/esp/bhaskix/boot.sig" "$WORK/wrong-sig/boot.sig"
rm -rf "$WORK/wrong-sig/esp"
(cd "$WORK/wrong-sig" && sha256sum bhaskixboot.efi boot.sig > SHA256SUMS)
if finish "$WORK/wrong-sig"; then
    fail "release-finish accepted a boot.sig made with the test key"
elif grep -q "boot.sig does not verify" "$WORK/finish.log"; then
    pass "release-finish refused a boot.sig made with a key other than the release's"
else
    fail "release-finish refused the test-key boot.sig for another reason: $(tail -1 "$WORK/finish.log")"
fi

exit "$status"
