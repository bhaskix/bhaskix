#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Assembles a release's files in one directory, and checks them rather than
# trusting the build that made them (docs/release-checklist.md):
#
#   bhaskix.iso      the Go server in, BusyBox out -- read back out of the ISO
#   bhaskixboot.efi  the native loader
#   LICENSE-go       Go's licence, because the server carries Go's runtime
#   SHA256SUMS       over the two binaries
#   to-sign/         only with release keys (RFC 0091 step 6): the loader and
#                    the boot set, for the offline machine to sign
#
#   tools/release-dist.sh ISO EFI GO_LICENSE OUT [TAG]
#
# RELEASE_BOOT_KEYS, from the environment, names the boot-set public keys the
# loader was built with, `:`-separated, or `none` -- the preview's. With keys,
# the loader must hold every one of them, and to-sign/ is written: the
# unsigned loader, the kernel and initrd read out of the ISO, a canonical
# boot.conf, and SHA256SUMS. `tools/release-keys.sh sign` signs it on the
# offline machine, and `make release-finish` checks what comes back.
#
# `make release-dist` runs it. With TAG, the tag must name the version both
# Cargo.toml files carry -- the workspace's, and the loader's, which is its own
# workspace and reports itself in every boot report -- so a release cannot ship
# saying `0.0.0`, as the loader did on 2026-10-19.
set -euo pipefail

if [[ $# -lt 4 ]]; then
    echo "usage: tools/release-dist.sh ISO EFI GO_LICENSE OUT [TAG]" >&2
    exit 2
fi
iso=$1 efi=$2 go_license=$3 out=$4 tag=${5:-}
cd "$(dirname "$0")/.."

fail() {
    echo "release-dist: $*" >&2
    exit 1
}

[[ -s $iso ]] || fail "no ISO at $iso"
[[ -s $efi ]] || fail "no loader at $efi"
[[ -s $go_license ]] || fail "no Go licence at $go_license"

# The version a TOML table declares, read without a TOML library: the first
# `version = "..."` line after the table's header and before the next one.
version_in() {
    awk -v table="$2" '
        $0 == table { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && /^version *=/ { gsub(/"/, "", $3); print $3; exit }
    ' "$1"
}

if [[ -n $tag ]]; then
    workspace=$(version_in Cargo.toml '[workspace.package]')
    loader=$(version_in boot/bhaskixboot/Cargo.toml '[package]')
    [[ -n $workspace && -n $loader ]] || fail "could not read a version from both Cargo.toml files"
    [[ $workspace == "$loader" ]] ||
        fail "the workspace says $workspace and the loader says $loader; a release names one version"
    [[ $tag == "v$workspace" || $tag == "v$workspace-"* ]] ||
        fail "tag $tag does not name version $workspace"
fi

# What the ISO carries, read back out of it. BusyBox stays out because its
# licence would oblige publishing its source; the Go server goes in.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
xorriso -osirrox on -indev "$iso" -extract /boot/initrd.tar "$work/initrd.tar" >/dev/null 2>&1 ||
    fail "could not read the initrd out of $iso"
member_size() {
    tar tvf "$work/initrd.tar" 2>/dev/null | awk -v name="./bin/$1" '$6 == name { print $3 }'
}
busybox=$(member_size busybox)
httpd=$(member_size httpd)
[[ -z $busybox || $busybox == 0 ]] || fail "the ISO carries a $busybox-byte BusyBox; the release leaves it out"
[[ -n $httpd && $httpd -gt 0 ]] || fail "the ISO carries no Go server; the release puts it in"

# RFC 0091 step 5: **the loader must not trust the published test key.** Whatever
# that key signed, anyone could have signed, so a release loader holding it
# would boot what anyone made. Read from the file that ships -- the key's 32
# public bytes anywhere in the image -- and not from how it was built.
test_key=tests/keys/bootsig-TEST-KEY.public
[[ -s $test_key ]] || fail "no test key at $test_key to check the loader against"
if python3 -I - "$efi" "$test_key" <<'PY'
import sys
image = open(sys.argv[1], "rb").read()
key = open(sys.argv[2], "rb").read()
sys.exit(0 if len(key) == 32 and key in image else 1)
PY
then
    fail "the loader trusts the published test key; build it with RELEASE_BOOT_KEYS naming release keys, or none"
fi

# RFC 0091 step 6: and with release keys named, **the loader holds each of
# them** -- the same question asked the other way, of the same file.
keys=${RELEASE_BOOT_KEYS:-none}
key_files=()
if [[ $keys != none ]]; then
    IFS=: read -ra key_files <<< "$keys"
    for key in "${key_files[@]}"; do
        [[ -s $key ]] || fail "RELEASE_BOOT_KEYS names $key, which is not there"
        python3 -I - "$efi" "$key" <<'PY' || fail "the loader does not hold $key, which RELEASE_BOOT_KEYS names"
import sys
image = open(sys.argv[1], "rb").read()
key = open(sys.argv[2], "rb").read()
sys.exit(0 if len(key) == 32 and key in image else 1)
PY
    done
    xorriso -osirrox on -indev "$iso" -extract /boot/bhaskix "$work/kernel" >/dev/null 2>&1 ||
        fail "could not read the kernel out of $iso"
fi

rm -rf "$out"
mkdir -p "$out"
cp "$iso" "$out/bhaskix.iso"
cp "$efi" "$out/bhaskixboot.efi"
cp "$go_license" "$out/LICENSE-go"
(cd "$out" && sha256sum bhaskix.iso bhaskixboot.efi > SHA256SUMS && sha256sum -c --quiet SHA256SUMS) ||
    fail "the sums did not check"

# What the offline machine signs: the loader for the firmware, and the boot set
# -- the kernel and initrd the ISO carries, and the boot.conf a signed boot
# uses -- for boot.sig. Its own sums, checked again there before anything is
# signed.
if (( ${#key_files[@]} > 0 )); then
    mkdir -p "$out/to-sign/bhaskix"
    cp "$efi" "$out/to-sign/bhaskixboot.efi"
    cp "$work/kernel" "$out/to-sign/bhaskix/kernel"
    cp "$work/initrd.tar" "$out/to-sign/bhaskix/initrd.tar"
    printf 'cmdline=\n' > "$out/to-sign/bhaskix/boot.conf"
    (cd "$out/to-sign" && sha256sum bhaskixboot.efi bhaskix/kernel bhaskix/initrd.tar bhaskix/boot.conf > SHA256SUMS)
    echo "release-dist: $out/to-sign/ is for the offline machine: tools/release-keys.sh sign $out/to-sign SIGNED"
fi

echo "release-dist: ${tag:-untagged} in $out/ -- BusyBox ${busybox:-absent}, Go server $httpd bytes, the loader trusting no test key"
(cd "$out" && ls -l bhaskix.iso bhaskixboot.efi LICENSE-go SHA256SUMS | awk '{ printf "  %10s  %s\n", $5, $9 }')
sed 's/^/  /' "$out/SHA256SUMS"
