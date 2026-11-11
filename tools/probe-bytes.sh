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
# **Data after a `probe_data:` label is data** (2026-11-11), because `objdump`
# cannot transcribe it: it decodes a string as instructions and folds a run of
# zero bytes into `...`, so the first probe with paths in it came out fifteen
# bytes short and was refused by the assertion below. From that label on, each
# label is one row -- its bytes from the binary, and a comment saying what they
# are -- and the same assertion covers the whole.
#
#   tools/probe-bytes.sh tools/probes/linux-lister.s LIST_PROBE_CODE
set -euo pipefail

source=${1:?usage: probe-bytes.sh <file.s> <CONST_NAME>}
name=${2:?usage: probe-bytes.sh <file.s> <CONST_NAME>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

as --64 -o "$work/probe.o" "$source"
# **No relocations: the bytes are copied, never linked** (2026-10-31). A
# reference to a global symbol -- `lea _start+0x20000(%rip)` -- assembles as a
# zero displacement and a relocation, and the copy below would have shipped the
# zero: RFC 0099's handler wrote into its own code until a local label replaced
# `_start`. Refused here, so it cannot be shipped quietly again.
if readelf -r "$work/probe.o" | grep -q 'R_X86_64'; then
    echo "probe-bytes: $source assembles with relocations, which a copy cannot apply:" >&2
    readelf -r "$work/probe.o" | grep 'R_X86_64' >&2
    exit 1
fi
objcopy -O binary --only-section=.text "$work/probe.o" "$work/probe.bin"
objdump -d "$work/probe.o" > "$work/probe.dis"
nm -n "$work/probe.o" > "$work/probe.syms"

CONST_NAME="$name" python3 - "$work/probe.bin" "$work/probe.dis" "$work/probe.syms" <<'PY'
import os, re, sys, pathlib

real = pathlib.Path(sys.argv[1]).read_bytes()

# The labels from `probe_data` on, grouped by address: two labels at one
# address are one row.
labels = {}
for line in pathlib.Path(sys.argv[3]).read_text().splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1] in "tT":
        labels.setdefault(int(parts[0], 16), []).append(parts[2])
data_at = next((at for at, names in labels.items() if "probe_data" in names), len(real))

rows, pending = [], None
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    m = re.match(r"\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(.*)$", line)
    if not m:
        continue
    if int(m.group(1), 16) >= data_at:
        break
    byts, mnem = m.group(2).split(), m.group(3).strip()
    # A continuation line: bytes with no mnemonic, belonging to the entry above.
    if mnem == "":
        assert pending is not None, "a continuation line before any instruction"
        pending[0].extend(byts)
        continue
    pending = (list(byts), re.sub(r"\s+", " ", mnem))
    rows.append(pending)


def says(names, chunk):
    """A data row's comment: its labels, and the string or zeros it holds."""
    named = ", ".join(n for n in names if n != "probe_data") or "probe_data"
    if chunk and all(b == 0 for b in chunk):
        return f"{named}: {len(chunk)} zero bytes"
    text = chunk.rstrip(b"\0")
    if chunk.endswith(b"\0") and all(0x20 <= b < 0x7F and b not in b'"\\' for b in text):
        return f'{named}: "{text.decode()}"'
    return f"{named}: {len(chunk)} bytes"


starts = sorted(at for at in labels if at >= data_at) if data_at < len(real) else []
for index, at in enumerate(starts):
    end = starts[index + 1] if index + 1 < len(starts) else len(real)
    chunk = real[at:end]
    if chunk:
        rows.append(([f"{b:02x}" for b in chunk], says(labels[at], chunk)))

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
