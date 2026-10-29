#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Assembles what goes on the removable medium for the key ceremony -- RFC 0091
# step 6. The offline machine has never been networked and never will be, so
# everything it needs beyond a fresh Ubuntu 26.04 LTS install travels here:
#
#   bootsign                  the boot-set signer, built on this host
#   release-keys.sh           the ceremony's commands
#   release-keys.md           the procedure
#   sbsigntool_*.deb          sbsign and sbverify, pinned by SHA-256
#   SOURCE                    the commit all of it came from
#   SHA256SUMS                over every file above
#
#   tools/ceremony-kit.sh OUT
#
# A fresh 26.04 install already carries what sbsigntool depends on (libc6,
# libssl3t64, libuuid1), and `openssl` and `python3`; RFC 0091 step 0 read
# those off a 26.04 container. `bootsign` is built here against glibc 2.31 and
# runs on 26.04's 2.43 -- read there with `ldd`, the same day -- so it is
# carried as built, after the same check here.
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: tools/ceremony-kit.sh OUT" >&2; exit 2; }
out=$1
cd "$(dirname "$0")/.."

fail() {
    echo "ceremony-kit: $*" >&2
    exit 1
}

# Ubuntu 26.04's sbsigntool, by its archive SHA-256, from Launchpad's
# librarian -- the archive's pool drops a version once it is superseded, and the
# librarian keeps every one it ever published (both read 2026-10-29).
SBSIGNTOOL_DEB=sbsigntool_0.9.4-3.1ubuntu9_amd64.deb
SBSIGNTOOL_SHA256=e8709091cc42e0053ef3736d03e7c4afcd1798424bbb04e41199e95ce2c3766e
SBSIGNTOOL_URL=https://launchpad.net/ubuntu/+archive/primary/+files/$SBSIGNTOOL_DEB

bootsign=target/x86_64-unknown-linux-gnu/release/bootsign
[[ -x $bootsign ]] || fail "no $bootsign -- make bootsign"

# Only the C library and its runtime: anything else might be missing on the
# offline machine, where nothing can be fetched.
extra=$(ldd "$bootsign" | awk '{ print $1 }' |
    grep -vE '^(linux-vdso\.so\.1|libc\.so\.6|libgcc_s\.so\.1|libpthread\.so\.0|libm\.so\.6|libdl\.so\.2|/lib64/ld-linux-x86-64\.so\.2)$' || true)
[[ -z $extra ]] || fail "bootsign links more than the C library: $extra"

[[ -e $out ]] && [[ -n "$(ls -A "$out" 2>/dev/null)" ]] && fail "$out is not empty"
mkdir -p "$out"
cp "$bootsign" "$out/bootsign"
cp tools/release-keys.sh "$out/release-keys.sh"
cp docs/release-keys.md "$out/release-keys.md"
chmod 755 "$out/bootsign" "$out/release-keys.sh"

curl -fsSL --max-time 120 -o "$out/$SBSIGNTOOL_DEB" "$SBSIGNTOOL_URL" ||
    fail "could not fetch $SBSIGNTOOL_URL"
echo "$SBSIGNTOOL_SHA256  $out/$SBSIGNTOOL_DEB" | sha256sum -c --quiet ||
    fail "$SBSIGNTOOL_DEB is not the one pinned here"

commit=$(git rev-parse HEAD)
dirty=$(git status --porcelain | head -1)
printf 'commit=%s\n%b' "$commit" "${dirty:+dirty=yes -- built from uncommitted changes, not for a real ceremony\n}" > "$out/SOURCE"
(cd "$out" && sha256sum bootsign release-keys.sh release-keys.md "$SBSIGNTOOL_DEB" SOURCE > SHA256SUMS)

echo "ceremony-kit: $out/, from $commit${dirty:+ (DIRTY)}"
sed 's/^/  /' "$out/SHA256SUMS"
echo "Copy $out to the medium; on the offline machine, docs/release-keys.md begins with checking these sums."
