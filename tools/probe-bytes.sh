#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Turns a hosted probe's assembly into the Rust byte array the kernel carries.
#
# The probes in `kernel/src/lib.rs` are machine code the kernel copies into a
# ring 3 page. Most of them were assembled by hand and carry their mnemonics in
# a comment column. This assembles one with `as` instead and transcribes it from
# `objdump`, so a byte and the comment beside it cannot disagree.
#
# **It verifies rather than trusts, and that is not decoration.** The first
# version of this transcription read only the first line of each `objdump`
# entry -- and `objdump` wraps an instruction longer than seven bytes onto a
# second line with no mnemonic on it. One `mov 0x230(%r12),%rdx` lost its
# trailing zero, every byte after it shifted by one, and the probe faulted in
# a ring 3 page at an address that looked exactly like a corrupted register.
# Two boots went into diagnosing a kernel that was working. So the bytes are
# taken from the assembled binary, `objdump` supplies only the comments, and
# the two are asserted equal before anything is printed.
#
#   tools/probe-bytes.sh tools/probes/linux-lister.s LIST_PROBE_CODE
set -euo pipefail

source=${1:?usage: probe-bytes.sh <file.s> <CONST_NAME>}
name=${2:?usage: probe-bytes.sh <file.s> <CONST_NAME>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

as --64 -o "$work/probe.o" "$source"
objcopy -O binary --only-section=.text "$work/probe.o" "$work/probe.bin"
objdump -d "$work/probe.o" > "$work/probe.dis"

CONST_NAME="$name" python3 - "$work/probe.bin" "$work/probe.dis" <<'PY'
import os, re, sys, pathlib

real = pathlib.Path(sys.argv[1]).read_bytes()
rows, pending = [], None
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    m = re.match(r"\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(.*)$", line)
    if not m:
        continue
    byts, mnem = m.group(2).split(), m.group(3).strip()
    # A continuation line: bytes with no mnemonic, belonging to the entry above.
    if mnem == "":
        assert pending is not None, "a continuation line before any instruction"
        pending[0].extend(byts)
        continue
    pending = (list(byts), re.sub(r"\s+", " ", mnem))
    rows.append(pending)

built = bytes(int(b, 16) for bs, _ in rows for b in bs)
assert built == real, (
    f"the transcription does not reproduce the assembled binary: "
    f"{len(built)} bytes against {len(real)}"
)

print(f"#[rustfmt::skip]")
print(f"const {os.environ['CONST_NAME']}: [u8; {len(built)}] = [")
for bs, mnem in rows:
    b = ", ".join("0x" + x for x in bs)
    print(f"    {b},{' ' * max(1, 41 - len(b))}// {mnem}")
print("];")
PY
