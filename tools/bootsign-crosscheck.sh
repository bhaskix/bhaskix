#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cross-checks `bootsign` against OpenSSL, in both directions (RFC 0091 step 2).
#
#   make bootsign && tools/bootsign-crosscheck.sh
#
# # Why
#
# `bhaskix-bootsig` is proven byte-exact against NIST's ACVP vectors, and that is
# the strong evidence. This is the independent kind: an implementation nobody
# here wrote, OpenSSL 3.5+, has to agree with ours about real signatures over a
# real statement. The build host has OpenSSL 1.1.1f, which predates SLH-DSA, so
# OpenSSL runs in an Ubuntu 26.04 container (3.5.5 when this was written).
#
# - **Direction one**: `bootsign` makes a key and signs an ESP's boot set, and
#   OpenSSL verifies the signature over the statement. A tampered statement must
#   then be refused.
# - **Direction two**: OpenSSL makes a key and signs the statement, and
#   `bootsign show` verifies it. A tampered signature must then be refused.
#
# The keys cross between the two as OpenSSL's own encodings. These are fixed
# prefixes in front of FIPS 205's raw bytes, read on 2026-10-29 from what
# OpenSSL 3.5.5 wrote for a key it generated (`openssl asn1parse`), not recalled:
#   - PKCS#8, 84 bytes: 20 bytes of prefix, then the 64-byte secret.
#   - SPKI, 50 bytes: 18 bytes of prefix, then the 32-byte public key.
# OID 2.16.840.1.101.3.4.3.20 is SLH-DSA-SHA2-128s.
#
# Not a gate: it needs Docker and an image, for `boot-on-ci-emulator.sh`'s reasons.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSIGN="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/bootsign"
IMAGE="${BHASKIX_OPENSSL_IMAGE:-bhaskix-openssl35}"
BASE="${BHASKIX_OPENSSL_BASE:-ubuntu:26.04}"
GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; DIM=$'\033[2m'; RESET=$'\033[0m'

SPKI_PREFIX='303030 0b0609608648016503040314 032100'
PKCS8_PREFIX='3052020100 300b0609608648016503040314 0440'

[[ -x "$BOOTSIGN" ]] || { echo "bootsign is not built -- run 'make bootsign'" >&2; exit 3; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || { echo "needs a reachable docker daemon -- this says nothing about bootsign" >&2; exit 3; }
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "${DIM}  building $IMAGE from $BASE (first run only)...${RESET}"
    docker build -q -t "$IMAGE" - >/dev/null <<EOF
FROM $BASE
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl \
 && rm -rf /var/lib/apt/lists/*
EOF
fi
openssl() { docker run --rm -v "$WORK:/w" -w /w "$IMAGE" openssl "$@"; }
hexbytes() { printf '%s' "$1" | tr -d ' ' | xxd -r -p; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "${DIM}  $(openssl version)${RESET}"

status=0
pass() { printf '%sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$1"; status=1; }

# An ESP with a boot set of its own.
mkdir -p "$WORK/esp/bhaskix"
printf '\177ELF a kernel for the cross-check' > "$WORK/esp/bhaskix/kernel"
printf 'an initrd' > "$WORK/esp/bhaskix/initrd.tar"
printf 'cmdline=\n' > "$WORK/esp/bhaskix/boot.conf"

# ---- Direction one: bootsign signs, OpenSSL verifies -----------------------
BHASKIX_KEYS="$WORK/keys" "$BOOTSIGN" keygen >/dev/null
secret=$(ls "$WORK"/keys/*.secret)
public=$(ls "$WORK"/keys/*.public)
"$BOOTSIGN" sign --key "$secret" "$WORK/esp" >/dev/null
head -c 128 "$WORK/esp/bhaskix/boot.sig" > "$WORK/statement"
tail -c +129 "$WORK/esp/bhaskix/boot.sig" > "$WORK/bootsign.sig"
{ hexbytes "$SPKI_PREFIX"; cat "$public"; } > "$WORK/bootsign-pub.der"
if openssl pkeyutl -verify -pubin -keyform DER -inkey bootsign-pub.der -rawin \
        -in statement -sigfile bootsign.sig >/dev/null 2>&1; then
    pass "OpenSSL verified a boot.sig signature bootsign made"
else
    fail "OpenSSL did not verify a boot.sig signature bootsign made"
fi
cp "$WORK/statement" "$WORK/statement.bent"
printf '\001' | dd of="$WORK/statement.bent" bs=1 seek=40 conv=notrunc status=none
if openssl pkeyutl -verify -pubin -keyform DER -inkey bootsign-pub.der -rawin \
        -in statement.bent -sigfile bootsign.sig >/dev/null 2>&1; then
    fail "OpenSSL verified bootsign's signature over a statement with a byte changed"
else
    pass "OpenSSL refused bootsign's signature over a statement with a byte changed"
fi

# ---- Direction two: OpenSSL signs, bootsign verifies -----------------------
openssl genpkey -algorithm SLH-DSA-SHA2-128s -outform DER -out openssl-key.der
if [[ "$(head -c 20 "$WORK/openssl-key.der" | xxd -p)" != "$(printf '%s' "$PKCS8_PREFIX" | tr -d ' ')" ]]; then
    fail "OpenSSL's private key is not the PKCS#8 layout read on 2026-10-29"
fi
tail -c 64 "$WORK/openssl-key.der" > "$WORK/openssl.secret"
tail -c 32 "$WORK/openssl.secret" > "$WORK/openssl.public"
# bootsign writes the statement this key would sign, and the signature beside
# it is replaced with OpenSSL's.
"$BOOTSIGN" sign --key "$WORK/openssl.secret" "$WORK/esp" >/dev/null
head -c 128 "$WORK/esp/bhaskix/boot.sig" > "$WORK/statement"
openssl pkeyutl -sign -keyform DER -inkey openssl-key.der -rawin -in statement -out openssl.sig
{ cat "$WORK/statement"; cat "$WORK/openssl.sig"; } > "$WORK/esp/bhaskix/boot.sig"
if "$BOOTSIGN" show "$WORK/esp" --public "$WORK/openssl.public" >/dev/null 2>&1; then
    pass "bootsign verified a boot.sig whose signature OpenSSL made ($(stat -c%s "$WORK/openssl.sig") bytes)"
else
    fail "bootsign did not verify a signature OpenSSL made"
fi
printf '\001' | dd of="$WORK/esp/bhaskix/boot.sig" bs=1 seek=4000 conv=notrunc status=none
if "$BOOTSIGN" show "$WORK/esp" --public "$WORK/openssl.public" >/dev/null 2>&1; then
    fail "bootsign verified OpenSSL's signature with a byte of it changed"
else
    pass "bootsign refused OpenSSL's signature with a byte of it changed"
fi

exit "$status"
