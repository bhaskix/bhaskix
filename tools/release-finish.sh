#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Takes what the offline machine signed back into a release, and checks it
# rather than trusting the medium it came on -- RFC 0091 step 6.
#
#   tools/release-finish.sh DIST SIGNED PUBLIC
#
# DIST is `make release-dist`'s output, with to-sign/ in it; SIGNED is what
# `tools/release-keys.sh sign` wrote (bhaskixboot.efi, boot.sig, SHA256SUMS);
# PUBLIC is the directory of committed public halves, boot/keys/. Before
# anything is assembled:
#
#   1. SIGNED matches its own sums;
#   2. the loader's signature verifies against the CA certificate in PUBLIC --
#      the certificate an owner enrols in `db`;
#   3. **the signed loader is the loader built here**, plus a signature and
#      nothing else: the signature removed and the PE checksum (which `sbsign`
#      fills in) zeroed on both sides, the two are byte for byte the same;
#   4. boot.sig verifies over to-sign's kernel, initrd and boot.conf with a
#      release key in PUBLIC.
#
# Then DIST gains the signed loader in place of the unsigned one, the boot set
# with its boot.sig under bhaskix/, the CA certificate an owner enrols, and
# SHA256SUMS over all of it; to-sign/ goes.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: tools/release-finish.sh DIST SIGNED PUBLIC" >&2
    exit 2
fi
dist=$1 signed=$2 public=$3
cd "$(dirname "$0")/.."

fail() {
    echo "release-finish: $*" >&2
    exit 1
}

bootsign=${BOOTSIGN:-target/x86_64-unknown-linux-gnu/release/bootsign}
[[ -x $bootsign ]] || fail "no bootsign at $bootsign (make bootsign builds it)"
command -v sbverify >/dev/null && command -v sbattach >/dev/null || fail "sbverify and sbattach are needed (sbsigntool)"
[[ -d $dist/to-sign ]] || fail "no $dist/to-sign -- make release-dist with RELEASE_BOOT_KEYS naming release keys"
[[ -s $public/db-ca.pem ]] || fail "no CA certificate at $public/db-ca.pem -- the ceremony's export goes in $public"
release_keys=("$public"/bootsig-release-*.public)
[[ -e ${release_keys[0]} ]] || fail "no boot-set public key in $public"

# 1.
[[ -f $signed/SHA256SUMS ]] || fail "no SHA256SUMS in $signed"
(cd "$signed" && sha256sum -c --quiet SHA256SUMS) || fail "$signed does not match its SHA256SUMS"
for file in bhaskixboot.efi boot.sig; do
    [[ -s $signed/$file ]] || fail "$signed has no $file"
done

# 2.
sbverify --cert "$public/db-ca.pem" "$signed/bhaskixboot.efi" >/dev/null 2>&1 ||
    fail "the loader's signature does not verify against $public/db-ca.pem"

# 3.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$signed/bhaskixboot.efi" "$work/stripped.efi"
sbattach --remove "$work/stripped.efi" >/dev/null 2>&1 || fail "could not remove the loader's signature to compare it"
python3 -I - "$work/stripped.efi" "$dist/to-sign/bhaskixboot.efi" <<'PY' ||
import struct
import sys


def without_checksum(path):
    data = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    # The optional header follows the 4-byte signature and the 20-byte COFF
    # header; its CheckSum is at offset 64 in both PE32 and PE32+.
    checksum = pe + 4 + 20 + 64
    data[checksum : checksum + 4] = b"\0\0\0\0"
    return bytes(data)


sys.exit(0 if without_checksum(sys.argv[1]) == without_checksum(sys.argv[2]) else 1)
PY
    fail "the signed loader is not the loader built here -- something besides a signature changed it"

# 4.
mkdir -p "$work/esp/bhaskix"
cp "$dist"/to-sign/bhaskix/kernel "$dist"/to-sign/bhaskix/initrd.tar "$dist"/to-sign/bhaskix/boot.conf "$work/esp/bhaskix/"
cp "$signed/boot.sig" "$work/esp/bhaskix/boot.sig"
publics=()
for key in "${release_keys[@]}"; do publics+=(--public "$key"); done
"$bootsign" show "$work/esp" "${publics[@]}" >/dev/null ||
    fail "boot.sig does not verify over the boot set with a release key in $public"

cp "$signed/bhaskixboot.efi" "$dist/bhaskixboot.efi"
rm -rf "$dist/bhaskix"
cp -r "$work/esp/bhaskix" "$dist/bhaskix"
cp "$public/db-ca.der" "$dist/bhaskix-secure-boot-ca.der" 2>/dev/null ||
    openssl x509 -in "$public/db-ca.pem" -outform DER -out "$dist/bhaskix-secure-boot-ca.der"
rm -rf "$dist/to-sign"
(cd "$dist" && sha256sum bhaskix.iso bhaskixboot.efi bhaskix-secure-boot-ca.der \
    bhaskix/kernel bhaskix/initrd.tar bhaskix/boot.conf bhaskix/boot.sig > SHA256SUMS &&
    sha256sum -c --quiet SHA256SUMS) || fail "the sums did not check"

echo "release-finish: $dist/ holds a signed loader and a signed boot set, each checked"
(cd "$dist" && find . -type f ! -name SHA256SUMS | sort | while read -r f; do printf '  %10s  %s\n' "$(stat -c %s "$f")" "${f#./}"; done)
