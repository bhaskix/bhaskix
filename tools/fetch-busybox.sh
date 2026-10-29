#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetches the one BusyBox the L1 corpus runs, and verifies it.
#
# **Pinned, because the runner's was a different program.** Until 2026-10-29
# the corpus was whatever static `/bin/busybox` the build machine had. On that
# day GitHub's `ubuntu-latest` became 26.04, whose image installs Ubuntu's
# **x86-64-v3 variant** packages, and CI run 874 went red on all six boot lanes:
# the v3 build traps at its first VEX instruction (`vmovdqa`), because Bhaskix
# never enables AVX state. Its own package note says so --
# `"architectureVariant":"amd64v3"`. Booted here under CI's QEMU 10.2.1, the v3
# build failed on both CPU models and this plain amd64 build passed all 175
# checks on both. Under this host's QEMU 4.2.1 the v3 build *runs*, so a local
# lane could never have seen it.
#
# The version and its sha256 are written here, and the package is checked
# against them **before** it is unpacked. Both were read on 2026-10-29 from the
# 26.04 package index apt had verified (`apt-cache show busybox-static`), not
# recalled. A package that does not match is deleted and the script fails.
#
# **The binary is checked as well as the package**: statically linked, and no
# `architectureVariant` in its package note. The hash already fixes the bytes;
# this check is for whoever moves the pin, so that the next build to assume a
# CPU feature Bhaskix does not enable is refused by name rather than found by a
# red lane.
#
# Idempotent: a binary already unpacked and passing both checks is used as it
# is. Prints the binary's path on success.
#
#   tools/fetch-busybox.sh [destination-root]      (default: build/toolchain)
# NOTICE: BusyBox
set -euo pipefail

VERSION=1.37.0-7ubuntu1
SHA256=fd605342f62268753076aa7d9321ff098b36ba53e47434145a9aedc28fd141a4
DEB="busybox-static_${VERSION}_amd64.deb"
URL="http://archive.ubuntu.com/ubuntu/pool/main/b/busybox/$DEB"

root=${1:-build/toolchain}
dest="$root/busybox-$VERSION"
busybox="$dest/usr/bin/busybox"

# Statically linked, and built for the plain x86-64 baseline. Prints why not.
unsuitable() {
    if ! [[ -f "$1" ]]; then
        echo "the package holds no such file"
    elif ! file -L "$1" 2>/dev/null | grep -q 'statically linked'; then
        echo "it is not statically linked"
    elif strings -a "$1" | grep -qF '"architectureVariant"'; then
        echo "its package note names an architecture variant: $(strings -a "$1" | grep -oE '"architectureVariant":"[^"]*"' | head -1)"
    fi
}

if [[ -x "$busybox" ]] && [[ -z "$(unsuitable "$busybox")" ]]; then
    echo "$busybox"
    exit 0
fi

mkdir -p "$root"
package="$root/$DEB"
if ! [[ -f "$package" ]] || ! echo "$SHA256  $package" | sha256sum -c --status - 2>/dev/null; then
    rm -f "$package"
    if ! curl -sSfL --max-time 300 -o "$package.part" "$URL"; then
        rm -f "$package.part"
        echo "fetch-busybox: could not download $URL -- no network, or the archive unreachable" >&2
        exit 1
    fi
    mv "$package.part" "$package"
fi
if ! echo "$SHA256  $package" | sha256sum -c --status -; then
    rm -f "$package"
    echo "fetch-busybox: $package does not match the pinned sha256 -- refused and deleted" >&2
    exit 1
fi

rm -rf "$dest.part"
mkdir -p "$dest.part"
dpkg-deb -x "$package" "$dest.part"
rm -rf "$dest"
mv "$dest.part" "$dest"
why="$(unsuitable "$busybox")"
if [[ -n "$why" ]]; then
    echo "fetch-busybox: $busybox is not one the corpus can run -- $why" >&2
    exit 1
fi
echo "$busybox"
