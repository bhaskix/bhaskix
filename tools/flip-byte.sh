#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Changes one byte of a file **for real**: writes the complement of what is
# there, so the result differs from the original whatever the byte held.
#
# The negative arms used to write a fixed value -- `printf '\377' | dd seek=N`
# -- which changes nothing on a byte that already holds it. On 2026-10-31 the
# Secure Boot lane's changed-kernel arm went red that way: byte 100000 of the
# kernel was already 0xff once RFC 0094 step 4 moved the layout, so the
# "changed" kernel was the signed one, verified, and booted. The signing was
# fine; the arm had never been able to tell a change from a no-op.
#
#   tools/flip-byte.sh FILE OFFSET
set -euo pipefail
file=${1:?usage: flip-byte.sh FILE OFFSET}
offset=${2:?usage: flip-byte.sh FILE OFFSET}
old="$(dd if="$file" bs=1 skip="$offset" count=1 status=none | od -An -tu1 | tr -d ' ')"
if [[ -z "$old" ]]; then
    echo "flip-byte: $file has no byte at $offset" >&2
    exit 1
fi
printf "\\$(printf '%03o' $(( old ^ 0xff )))" | dd of="$file" bs=1 seek="$offset" conv=notrunc status=none
