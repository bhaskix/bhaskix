#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The release keys of RFC 0091, made and used on the project lead's offline
# machine -- step 6. docs/release-keys.md is the procedure; this is the part of
# it a machine can do without being trusted to remember.
#
#   release-keys.sh [--rehearsal] init                 make the three keys
#   release-keys.sh [--rehearsal] export DIR           their public halves, and nothing else
#   release-keys.sh [--rehearsal] sign BUNDLE OUT      sign a release's loader and boot set
#   release-keys.sh [--rehearsal] rotate-leaf          a new signing leaf under the same CA
#   release-keys.sh [--rehearsal] rotate-bootset       a new boot-set key, for loaders built after it
#   release-keys.sh [--rehearsal] backup DIR           an encrypted copy, for one offline medium
#   release-keys.sh [--rehearsal] restore ARCHIVE      that copy back, into an empty key directory
#
# **Two keys for two links** (RFC 0091, *The chain*):
#
#   - the firmware-facing key: an offline **CA**, RSA-2048 with SHA-256 -- the
#     one combination every Secure Boot firmware must verify (UEFI 2.10 s2.6.5)
#     -- whose certificate an owner enrols in `db`, and a **signing leaf**
#     beneath it that `sbsign`s each loader, so a leaf can be rotated without
#     any owner re-enrolling (question 5);
#   - the boot-set key: SLH-DSA-SHA2-128s, made by `bootsign keygen`, whose
#     public half is compiled into each release's loader and whose signature is
#     `bhaskix\boot.sig` (question 1).
#
# **Where they live** (questions 3, 4 and 7, decided 2026-10-29): with the lead
# alone, in $BHASKIX_RELEASE_KEYS (default ~/.bhaskix-release-keys, mode 0700) on
# a machine that has never been networked and whose disk is encrypted; and in
# two encrypted backups on two offline media kept in two places. Never in a git
# work tree -- this script refuses one, and `make gates` refuses a tracked
# secret -- and never in a cloud KMS.
#
# **It refuses to run with a network interface up**, other than loopback. That
# is not proof the machine was never networked -- nothing a program can read
# is -- but it stops the commonest slip, a cable or a Wi-Fi association
# nobody noticed. `--rehearsal` skips that one check, writes REHEARSAL into
# every name it makes, and refuses the default key directory: the boot test
# rehearses the whole ceremony with throwaway keys, so that the procedure the
# lead runs is the one that was tested.
set -euo pipefail

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'
die() { printf '%srefused%s  %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
ok() { printf '%sok%s       %s\n' "$GREEN" "$RESET" "$*"; }

# The published test key's public half (tests/keys/bootsig-TEST-KEY.public),
# written out so this script needs no checkout: a loader holding it trusts
# whatever anyone signs, and is never signed here.
TEST_KEY_HEX=5b01f28b26142afbd62d27bafe72ab373f783d80aa038dd4b5256aa0b123ac28

rehearsal=0
if [[ "${1:-}" == --rehearsal ]]; then
    rehearsal=1
    shift
fi
command="${1:-}"
[[ -n "$command" ]] || die "no command: init, export, sign, rotate-leaf, rotate-bootset, backup or restore"
shift

if (( rehearsal )); then
    [[ -n "${BHASKIX_RELEASE_KEYS:-}" ]] ||
        die "--rehearsal needs BHASKIX_RELEASE_KEYS naming a throwaway directory, never the default"
    keys="$BHASKIX_RELEASE_KEYS"
    who="REHEARSAL Bhaskix (not a release key)"
    printf '%sREHEARSAL%s  throwaway keys in %s -- nothing made here may sign a release\n' \
        "$YELLOW" "$RESET" "$keys"
else
    keys="${BHASKIX_RELEASE_KEYS:-$HOME/.bhaskix-release-keys}"
    who="Bhaskix"
fi
year="$(date -u +%Y)"
ca_subject="/O=$who/CN=$who Secure Boot CA $year"

bootsign="${BOOTSIGN:-$(dirname "$(readlink -f "$0")")/bootsign}"
[[ -x "$bootsign" ]] || bootsign="$(command -v bootsign || true)"

# --- refusals ------------------------------------------------------------

# A directory inside a git work tree is one `git add` from being published.
# Walked by hand: the offline machine need not have git.
in_work_tree() {
    local dir
    dir="$(readlink -m "$1")"
    while :; do
        [[ -e "$dir/.git" ]] && return 0
        [[ "$dir" == / ]] && return 1
        dir="$(dirname "$dir")"
    done
}

no_network() {
    (( rehearsal )) && return 0
    local iface state up=()
    for iface in /sys/class/net/*; do
        [[ "$(basename "$iface")" == lo ]] && continue
        state="$(cat "$iface/operstate" 2>/dev/null || echo unknown)"
        [[ "$state" == down || "$state" == notpresent ]] || up+=("$(basename "$iface") ($state)")
    done
    (( ${#up[@]} == 0 )) ||
        die "a network interface is not down: ${up[*]} -- this machine must be offline (docs/release-keys.md)"
}

need() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed (the ceremony kit carries it)"
    done
}

need_bootsign() {
    [[ -n "$bootsign" && -x "$bootsign" ]] ||
        die "no bootsign beside this script, in BOOTSIGN, or on PATH (the ceremony kit carries it)"
}

key_dir() {
    in_work_tree "$keys" && die "$keys is inside a git work tree; keys must live outside every checkout"
    [[ -d "$keys" ]] || die "no key directory at $keys -- run init first"
    local file
    for file in db-ca.key db-ca.pem db-ca.der leaf.key leaf.pem; do
        [[ -s "$keys/$file" ]] || die "$keys has no $file -- an incomplete key set, which nothing here will use"
    done
    bootset_key >/dev/null
}

# The boot-set key: the one `boot-*.secret` in $keys/bootsig.
bootset_key() {
    local found=("$keys"/bootsig/boot-*.secret)
    [[ -e "${found[0]}" ]] || die "no boot-set key in $keys/bootsig"
    (( ${#found[@]} == 1 )) || die "more than one boot-set key in $keys/bootsig: ${found[*]}"
    printf '%s\n' "${found[0]}"
}

# Whether file $1 holds the 32 bytes of file $2 anywhere -- the way
# tools/release-dist.sh asks it, from the file and not from how it was built.
holds_key() {
    python3 -I - "$1" "$2" <<'PY'
import sys
image = open(sys.argv[1], "rb").read()
key = open(sys.argv[2], "rb").read()
sys.exit(0 if len(key) == 32 and key in image else 1)
PY
}

# A configuration of this script's own, so the system's `openssl.cnf` adds
# nothing: Ubuntu's `v3_ca` section adds Basic Constraints and a key identifier
# of its own, and a certificate carrying each twice is invalid (RFC 5280
# s4.2) -- the first rehearsal's CA did exactly that, and its leaf would not
# verify. $1 names the x509v3 section to apply to a self-signed request, or is
# empty for a plain request.
openssl_config() {
    printf '%s\n' "[req]" "distinguished_name = dn" "prompt = no"
    [[ -n "$1" ]] && printf 'x509_extensions = %s\n' "$1"
    printf '%s\n' "[dn]" "[ca]" \
        "basicConstraints = critical, CA:TRUE" \
        "keyUsage = critical, keyCertSign, cRLSign" \
        "subjectKeyIdentifier = hash"
}

# A leaf certificate and key, signed by the CA: $1 is the name, $2 its serial.
make_leaf() {
    local name="$1" serial="$2" ext
    ext="$(mktemp)"
    printf '%s\n' \
        "basicConstraints = critical, CA:FALSE" \
        "keyUsage = critical, digitalSignature" \
        "extendedKeyUsage = codeSigning" \
        "subjectKeyIdentifier = hash" \
        "authorityKeyIdentifier = keyid" > "$ext"
    openssl req -new -newkey rsa:2048 -nodes -sha256 -config <(openssl_config "") \
        -subj "/O=$who/CN=$who Secure Boot Signing $year-$serial" \
        -keyout "$keys/$name.key" -out "$keys/$name.csr" 2>/dev/null
    openssl x509 -req -in "$keys/$name.csr" -sha256 -days 1826 \
        -CA "$keys/db-ca.pem" -CAkey "$keys/db-ca.key" -set_serial "$serial" \
        -extfile "$ext" -out "$keys/$name.pem" 2>/dev/null
    rm -f "$keys/$name.csr" "$ext"
    chmod 600 "$keys/$name.key"
    openssl verify -CAfile "$keys/db-ca.pem" "$keys/$name.pem" >/dev/null ||
        die "the new leaf does not verify against the CA"
}

fingerprints() {
    local secret id
    secret="$(bootset_key)"
    id="$(basename "$secret" .secret)"
    printf '  db certificate   %s\n' "$(openssl x509 -in "$keys/db-ca.pem" -noout -subject | sed 's/^subject=//')"
    printf '                   SHA-256 %s\n' "$(openssl x509 -in "$keys/db-ca.pem" -noout -fingerprint -sha256 | sed 's/.*=//')"
    printf '  signing leaf     %s\n' "$(openssl x509 -in "$keys/leaf.pem" -noout -subject | sed 's/^subject=//')"
    printf '  boot-set key     %s\n' "${id#boot-}"
}

# --- commands ------------------------------------------------------------

init() {
    (( $# == 0 )) || die "init takes nothing"
    no_network
    need openssl python3
    need_bootsign
    in_work_tree "$keys" && die "$keys is inside a git work tree; keys must live outside every checkout"
    if [[ -e "$keys" ]] && [[ -n "$(ls -A "$keys" 2>/dev/null)" ]]; then
        die "$keys is not empty; init never overwrites a key (rotate-leaf makes a new leaf)"
    fi
    umask 077
    mkdir -p "$keys"
    chmod 700 "$keys"

    # The CA: thirty years, because owners enrol it once; the firmware this was
    # tested on ignores certificate expiry altogether (RFC 0091 step 0).
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 10957 -config <(openssl_config ca) \
        -subj "$ca_subject" -keyout "$keys/db-ca.key" -out "$keys/db-ca.pem" 2>/dev/null
    chmod 600 "$keys/db-ca.key"
    openssl x509 -in "$keys/db-ca.pem" -outform DER -out "$keys/db-ca.der"
    ok "the CA: RSA-2048, SHA-256, thirty years"

    # The first leaf: five years, rotated under the same CA when it is due.
    make_leaf leaf 1
    ok "the signing leaf: RSA-2048, code signing, five years, serial 1"

    BHASKIX_KEYS="$keys/bootsig" "$bootsign" keygen >/dev/null
    ok "the boot-set key: SLH-DSA-SHA2-128s"
    echo
    fingerprints
    echo
    echo "Next: back up to two media (backup), then export the public halves (export)."
}

export_public() {
    (( $# == 1 )) || die "export takes DIR"
    key_dir
    local out="$1" secret id
    case "$(readlink -m "$out")/" in "$(readlink -m "$keys")"/*) die "export must not write inside $keys" ;; esac
    mkdir -p "$out"
    secret="$(bootset_key)"
    id="$(basename "$secret" .secret)"
    cp "$keys/db-ca.pem" "$keys/db-ca.der" "$keys/leaf.pem" "$out/"
    cp "$keys/bootsig/$id.public" "$out/bootsig-release-${id#boot-}.public"
    # Nothing secret may have followed: checked on what was written.
    if compgen -G "$out/*.key" >/dev/null || compgen -G "$out/*.secret" >/dev/null ||
        grep -lq "PRIVATE KEY" "$out"/* 2>/dev/null; then
        die "a secret reached $out -- remove it before that medium leaves this machine"
    fi
    (cd "$out" && sha256sum db-ca.pem db-ca.der leaf.pem "bootsig-release-${id#boot-}.public" > SHA256SUMS)
    ok "public halves in $out"
    fingerprints
}

sign() {
    (( $# == 2 )) || die "sign takes BUNDLE OUT"
    no_network
    key_dir
    need openssl sbsign sbverify python3 sha256sum
    need_bootsign
    local bundle="$1" out="$2" secret public test_key work
    [[ -f "$bundle/SHA256SUMS" ]] || die "no SHA256SUMS in $bundle -- is it make release-dist's to-sign directory?"
    (cd "$bundle" && sha256sum -c --quiet SHA256SUMS) || die "$bundle does not match its SHA256SUMS"
    for file in bhaskixboot.efi bhaskix/kernel bhaskix/initrd.tar bhaskix/boot.conf; do
        [[ -f "$bundle/$file" ]] || die "$bundle has no $file"
    done
    secret="$(bootset_key)"
    public="${secret%.secret}.public"
    test_key="$(mktemp)"
    python3 -I -c "import sys; sys.stdout.buffer.write(bytes.fromhex('$TEST_KEY_HEX'))" > "$test_key"
    holds_key "$bundle/bhaskixboot.efi" "$test_key" &&
        die "the loader holds the published test key; it would boot whatever anyone signs"
    holds_key "$bundle/bhaskixboot.efi" "$public" ||
        die "the loader does not hold this boot-set key ($(basename "$public" .public)); it would refuse what is signed here"
    rm -f "$test_key"
    if sbverify --list "$bundle/bhaskixboot.efi" 2>/dev/null | grep -q "signature 1"; then
        die "the loader is already signed; sign the unsigned one make release-dist wrote"
    fi

    mkdir -p "$out"
    sbsign --key "$keys/leaf.key" --cert "$keys/leaf.pem" \
        --output "$out/bhaskixboot.efi" "$bundle/bhaskixboot.efi" >/dev/null 2>&1 ||
        die "sbsign could not sign the loader"
    sbverify --cert "$keys/db-ca.pem" "$out/bhaskixboot.efi" >/dev/null 2>&1 ||
        die "the signed loader does not verify against the CA"
    ok "the loader, signed by the leaf; it verifies against the CA"

    work="$(mktemp -d)"
    mkdir -p "$work/bhaskix"
    cp "$bundle"/bhaskix/kernel "$bundle"/bhaskix/initrd.tar "$bundle"/bhaskix/boot.conf "$work/bhaskix/"
    "$bootsign" sign --key "$secret" "$work" >/dev/null || die "bootsign could not sign the boot set"
    "$bootsign" show "$work" --public "$public" >/dev/null ||
        die "the boot set does not verify with its own key"
    cp "$work/bhaskix/boot.sig" "$out/boot.sig"
    rm -rf "$work"
    ok "boot.sig, over the kernel, the initrd and boot.conf; it verifies"
    (cd "$out" && sha256sum bhaskixboot.efi boot.sig > SHA256SUMS)
    echo "Take $out back to the build host: make release-finish SIGNED=$out"
}

rotate_leaf() {
    (( $# == 0 )) || die "rotate-leaf takes nothing"
    no_network
    key_dir
    need openssl
    local hex serial
    hex="$(openssl x509 -in "$keys/leaf.pem" -noout -serial | cut -d= -f2)"
    serial=$(( 16#$hex + 1 ))
    mkdir -p "$keys/retired"
    mv "$keys/leaf.key" "$keys/retired/leaf-$(( serial - 1 )).key"
    mv "$keys/leaf.pem" "$keys/retired/leaf-$(( serial - 1 )).pem"
    make_leaf leaf "$serial"
    ok "a new signing leaf, serial $serial; the old one is in $keys/retired"
    echo "Owners enrolled the CA, not the leaf, so nothing changes on their machines."
    echo "If the old leaf was lost rather than retired, revoke it: docs/release-keys.md, *Revoke*."
}

# A new boot-set key. Each loader release compiles in the key of its day
# (question 5), so this changes nothing already shipped: loaders built before
# it go on trusting the old key, which is why losing one means revoking those
# loaders by hash in `dbx` (docs/release-keys.md, *Revoke*).
rotate_bootset() {
    (( $# == 0 )) || die "rotate-bootset takes nothing"
    no_network
    key_dir
    need_bootsign
    local secret id
    secret="$(bootset_key)"
    id="$(basename "$secret" .secret)"
    mkdir -p "$keys/retired"
    mv "$keys/bootsig/$id.secret" "$keys/bootsig/$id.public" "$keys/retired/"
    BHASKIX_KEYS="$keys/bootsig" "$bootsign" keygen >/dev/null
    secret="$(bootset_key)"
    ok "a new boot-set key, $(basename "$secret" .secret | sed 's/^boot-//'); ${id#boot-} is in $keys/retired"
    echo "Export again: the next release's loader is built with the new public half."
}

backup() {
    (( $# == 1 )) || die "backup takes DIR, the mounted medium"
    key_dir
    need openssl tar sha256sum
    local dir="$1" archive pass
    archive="$dir/bhaskix-release-keys-$(date -u +%Y%m%dT%H%M%SZ).tar.enc"
    if (( rehearsal )); then
        [[ -n "${BHASKIX_BACKUP_PASS:-}" ]] || die "--rehearsal backup reads its passphrase from BHASKIX_BACKUP_PASS"
        pass=(-pass env:BHASKIX_BACKUP_PASS)
    else
        [[ -z "${BHASKIX_BACKUP_PASS:-}" ]] || die "a real backup's passphrase is typed, never read from the environment"
        pass=()
    fi
    tar -C "$keys" -cf - . |
        openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt "${pass[@]}" -out "$archive"
    # Read back before anyone trusts it: decrypted into a scratch directory on
    # this machine's encrypted disk and compared, file by file, with the keys.
    local check
    check="$(mktemp -d)"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 "${pass[@]}" -in "$archive" | tar -C "$check" -xf -
    if ! diff -r "$keys" "$check" >/dev/null; then
        rm -rf "$check"
        die "the backup read back differently from $keys -- do not rely on it"
    fi
    rm -rf "$check"
    sha256sum "$archive" > "$archive.sha256"
    ok "an encrypted backup: $archive"
    echo "Make the second on another medium, and keep the two in two places."
}

restore() {
    (( $# == 1 )) || die "restore takes ARCHIVE"
    need openssl tar
    in_work_tree "$keys" && die "$keys is inside a git work tree"
    if [[ -e "$keys" ]] && [[ -n "$(ls -A "$keys" 2>/dev/null)" ]]; then
        die "$keys is not empty; restore writes only into an empty key directory"
    fi
    local archive="$1" pass
    [[ -f "$archive.sha256" ]] && { sha256sum -c --quiet "$archive.sha256" || die "$archive does not match its .sha256"; }
    if (( rehearsal )); then pass=(-pass env:BHASKIX_BACKUP_PASS); else pass=(); fi
    umask 077
    mkdir -p "$keys"
    chmod 700 "$keys"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 "${pass[@]}" -in "$archive" | tar -C "$keys" -xf -
    ok "restored into $keys"
    fingerprints
}

case "$command" in
    init) init "$@" ;;
    export) export_public "$@" ;;
    sign) sign "$@" ;;
    rotate-leaf) rotate_leaf "$@" ;;
    rotate-bootset) rotate_bootset "$@" ;;
    backup) backup "$@" ;;
    restore) restore "$@" ;;
    *) die "unknown command $command: init, export, sign, rotate-leaf, rotate-bootset, backup or restore" ;;
esac
