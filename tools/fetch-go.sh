#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetches the one Go toolchain this project builds with, and verifies it.
#
# **Pinned, because two Gos were two binaries.** Until 2026-10-01 the Go corpus
# was built with whatever `go` the machine had: go 1.13.8 on the build host and
# go 1.24.13 on CI, eleven minor versions apart and across 1.14's signal-based
# preemption -- so a trace taken here was not the list of calls CI's binary
# made, and a pass in one said little about the other (RFC 0086, unresolved
# question 1). The project lead pinned **go 1.27.1** on 2026-10-01.
#
# The version and its sha256 are written here, and the tarball is checked
# against them **before** it is unpacked. The checksum was read from go.dev's
# own download list (`https://go.dev/dl/?mode=json`) on 2026-10-01, not
# recalled. A tarball that does not match is deleted and the script fails: a
# toolchain nobody can vouch for is worse than none, because none is reported
# as absent and a wrong one is not reported at all.
#
# Idempotent: a toolchain already unpacked and answering to the right version
# is used as it is. Prints the `go` binary's path on success.
#
#   tools/fetch-go.sh [destination-root]      (default: build/toolchain)
set -euo pipefail

VERSION=1.27.1
SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
URL="https://go.dev/dl/go${VERSION}.linux-amd64.tar.gz"

root=${1:-build/toolchain}
dest="$root/go$VERSION"
go="$dest/bin/go"

if [[ -x "$go" ]] && [[ "$(GOTOOLCHAIN=local "$go" env GOVERSION 2>/dev/null)" == "go$VERSION" ]]; then
    echo "$go"
    exit 0
fi

mkdir -p "$root"
tarball="$root/go$VERSION.linux-amd64.tar.gz"
if ! [[ -f "$tarball" ]] || ! echo "$SHA256  $tarball" | sha256sum -c --status - 2>/dev/null; then
    rm -f "$tarball"
    if ! curl -sSfL --max-time 600 -o "$tarball.part" "$URL"; then
        rm -f "$tarball.part"
        echo "fetch-go: could not download $URL -- no network, or go.dev unreachable" >&2
        exit 1
    fi
    mv "$tarball.part" "$tarball"
fi
if ! echo "$SHA256  $tarball" | sha256sum -c --status -; then
    rm -f "$tarball"
    echo "fetch-go: $tarball does not match the pinned sha256 -- refused and deleted" >&2
    exit 1
fi

rm -rf "$dest.part"
mkdir -p "$dest.part"
tar -xzf "$tarball" -C "$dest.part" --strip-components=1
rm -rf "$dest"
mv "$dest.part" "$dest"
if [[ "$(GOTOOLCHAIN=local "$go" env GOVERSION)" != "go$VERSION" ]]; then
    echo "fetch-go: the unpacked toolchain does not say go$VERSION" >&2
    exit 1
fi
echo "$go"
