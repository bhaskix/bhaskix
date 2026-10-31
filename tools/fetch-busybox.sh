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
# **`BUSYBOX_VARIANT=amd64v3` fetches the other one** -- RFC 0094 step 5
# (2026-10-31): the same version built for x86-64-v3, the build run 874 met,
# for the lane that proves it now runs. Its hash was read on 2026-10-31 from
# the 26.04 `binary-amd64v3` index, whose own hash was checked against the
# archive's signed `InRelease` (`gpgv`, the Ubuntu archive key). The binary
# check is turned round for it: it must carry the variant note, so a plain
# build cannot stand in for it and make the lane prove nothing.
#
#   tools/fetch-busybox.sh [destination-root]      (default: build/toolchain)
#   BUSYBOX_VARIANT=amd64v3 tools/fetch-busybox.sh [destination-root]
# NOTICE: BusyBox
set -euo pipefail

VERSION=1.37.0-7ubuntu1
VARIANT=${BUSYBOX_VARIANT:-}
case "$VARIANT" in
    "")
        SHA256=fd605342f62268753076aa7d9321ff098b36ba53e47434145a9aedc28fd141a4
        DEB="busybox-static_${VERSION}_amd64.deb"
        suffix=""
        ;;
    amd64v3)
        SHA256=b51a2bcb9dd0484f7920441937dda97da2752df94964126dffe59a8332775b4c
        DEB="busybox-static_${VERSION}_amd64v3.deb"
        suffix="-amd64v3"
        ;;
    *)
        echo "fetch-busybox: no pinned build for variant '$VARIANT'" >&2
        exit 1
        ;;
esac
URL="http://archive.ubuntu.com/ubuntu/pool/main/b/busybox/$DEB"

root=${1:-build/toolchain}
dest="$root/busybox-$VERSION$suffix"
busybox="$dest/usr/bin/busybox"

# Statically linked, and built for the variant asked for: the plain x86-64
# baseline unless one was named. Prints why not.
unsuitable() {
    local note
    if ! [[ -f "$1" ]]; then
        echo "the package holds no such file"
        return
    elif ! file -L "$1" 2>/dev/null | grep -q 'statically linked'; then
        echo "it is not statically linked"
        return
    fi
    note="$(strings -a "$1" | grep -oE '"architectureVariant":"[^"]*"' | head -1 || true)"
    if [[ -z "$VARIANT" && -n "$note" ]]; then
        echo "its package note names an architecture variant: $note"
    elif [[ -n "$VARIANT" && "$note" != "\"architectureVariant\":\"$VARIANT\"" ]]; then
        echo "its package note does not name $VARIANT: ${note:-no variant at all}"
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
