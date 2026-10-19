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
#
#   tools/release-dist.sh ISO EFI GO_LICENSE OUT [TAG]
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

rm -rf "$out"
mkdir -p "$out"
cp "$iso" "$out/bhaskix.iso"
cp "$efi" "$out/bhaskixboot.efi"
cp "$go_license" "$out/LICENSE-go"
(cd "$out" && sha256sum bhaskix.iso bhaskixboot.efi > SHA256SUMS && sha256sum -c --quiet SHA256SUMS) ||
    fail "the sums did not check"

echo "release-dist: ${tag:-untagged} in $out/ -- BusyBox ${busybox:-absent}, Go server $httpd bytes"
(cd "$out" && ls -l bhaskix.iso bhaskixboot.efi LICENSE-go SHA256SUMS | awk '{ printf "  %10s  %s\n", $5, $9 }')
sed 's/^/  /' "$out/SHA256SUMS"
