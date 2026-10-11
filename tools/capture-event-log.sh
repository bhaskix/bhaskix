#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Captures the event log a native boot hands the kernel -- RFC 0089 step 4's
# fixture.
#
#   tools/capture-event-log.sh <out.eventlog> [loader.efi kernel initrd]
#
# Not `.bin` or `.log`: `.gitignore` takes both for build output.
#
# Boots `bhaskixboot.efi` under OVMF with a fresh swtpm (`tools/swtpm.sh`), the
# command line the native lanes use, and a QEMU monitor; waits for the replay's
# verdict; stops the guest and dumps its memory; and writes out **the loader's
# copy of the log** -- the bytes the kernel and `bin/tpmd` read, the final
# events appended. It is found by its header's signature and chosen by its
# length, which must equal what the loader said it copied plus what it
# appended. Every copy of that length must be byte-identical, or nothing is
# written.
#
# Then it replays the log **with its own walker and Python's `hashlib`** -- an
# implementation apart from `bhaskix-tcglog` and `bhaskix-pkg` -- and prints the
# values a test can pin, beside the boot's own PCR and verdict lines, which
# carry what the TPM itself held.
#
# Defaults are the build's outputs, as `tests/qemu/native-boot-test.sh` uses.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: tools/capture-event-log.sh <out.eventlog> [loader.efi kernel initrd]}"
LOADER="${2:-$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi}"
KERNEL="${3:-$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix}"
INITRD="${4:-$REPO_ROOT/build/initrd.tar}"
OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
TIMEOUT=120
MEMORY_MIB=256

for file in "$LOADER" "$KERNEL" "$INITRD" "$OVMF_CODE" "$OVMF_VARS"; do
    [[ -f "$file" ]] || { echo "missing: $file" >&2; exit 1; }
done

WORK="$(mktemp -d)"
TPM_DIR="$WORK/tpm"
mkdir -p "$TPM_DIR" "$WORK/esp/EFI/BOOT" "$WORK/esp/bhaskix"
cleanup() { "$REPO_ROOT/tools/swtpm.sh" stop "$TPM_DIR" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

cp "$LOADER" "$WORK/esp/EFI/BOOT/BOOTX64.EFI"
cp "$KERNEL" "$WORK/esp/bhaskix/kernel"
cp "$INITRD" "$WORK/esp/bhaskix/initrd.tar"
printf 'cmdline=kaslr=show\n' > "$WORK/esp/bhaskix/boot.conf"
cp "$OVMF_VARS" "$WORK/vars.fd"

"$REPO_ROOT/tools/swtpm.sh" start "$TPM_DIR"
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"
qemu_tpm_args "$TPM_DIR/swtpm.sock"

SERIAL="$WORK/serial.log"
MONITOR="$WORK/monitor.sock"
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -cpu max -smp 4 -m "$MEMORY_MIB" -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WORK/vars.fd" \
    -drive "format=raw,file=fat:rw:$WORK/esp" \
    "${TPM_ARGS[@]}" \
    -serial "file:$SERIAL" \
    -qmp "unix:$MONITOR,server,nowait" \
    >/dev/null 2>&1 &
QEMU=$!

verdict="tpm            (log and TPM agree|log not checked|FAILED)"
for _ in $(seq 1 "$TIMEOUT"); do
    grep -qaE "$verdict" "$SERIAL" 2>/dev/null && break
    kill -0 "$QEMU" 2>/dev/null || break
    sleep 1
done
if ! grep -qaE "$verdict" "$SERIAL" 2>/dev/null; then
    kill "$QEMU" 2>/dev/null || true
    echo "no verdict line within ${TIMEOUT}s; nothing captured" >&2
    exit 1
fi

# Through QMP, not the human monitor: QMP answers a command when it has
# finished, where the human monitor echoes keystrokes and a socket closed
# early drops the line (2026-10-11). Not stopped first either: QEMU 4.2.1
# here segfaulted around `stop` and `quit` with the TPM emulator attached,
# and the guest is idle at its shell by the verdict, its log copy written
# once before the kernel started.
python3 - "$MONITOR" "$WORK/memory.bin" "$MEMORY_MIB" <<'PY'
import json, socket, sys
path, out, mib = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_UNIX)
s.connect(path)
stream = s.makefile("rw")
def answer():
    while True:
        reply = json.loads(stream.readline())
        if "return" in reply or "error" in reply:
            return reply
def ask(command, **arguments):
    stream.write(json.dumps({"execute": command, "arguments": arguments}) + "\n")
    stream.flush()
    reply = answer()
    if "error" in reply:
        sys.exit(f"{command}: {reply['error']}")
json.loads(stream.readline())  # the greeting
ask("qmp_capabilities")
ask("pmemsave", val=0, size=mib * 1024 * 1024, filename=out)
PY
kill "$QEMU" 2>/dev/null || true
wait "$QEMU" 2>/dev/null || true

copied=$(grep -aoE "bhaskixboot: event log [0-9]+ bytes copied" "$SERIAL" | grep -oE '[0-9]+' | head -1)
appended=$(grep -aoE "bhaskixboot: final events [0-9]+ \([0-9]+ bytes\)" "$SERIAL" | grep -oE '\([0-9]+' | tr -d '(' | head -1)
[[ -n "$copied" && -n "$appended" ]] || { echo "the loader did not say what it copied" >&2; exit 1; }

python3 - "$WORK/memory.bin" "$((copied + appended))" "$OUT" <<'PY'
import hashlib, struct, sys

dump = open(sys.argv[1], "rb").read()
want = int(sys.argv[2])
out = sys.argv[3]
SPEC = b"Spec ID Event03\0"
SHA256 = 0x000B
EV_NO_ACTION = 3
EV_EFI_HCRTM_EVENT = 0x80000010

def walk(start):
    """This tool's own reading of a crypto-agile log at `start`."""
    try:
        pcr, kind = struct.unpack_from("<II", dump, start)
        size, = struct.unpack_from("<I", dump, start + 28)
    except struct.error:
        return None
    data = dump[start + 32:start + 32 + size]
    if pcr != 0 or kind != EV_NO_ACTION or not data.startswith(SPEC):
        return None
    count, = struct.unpack_from("<I", data, 24)
    banks = dict(struct.unpack_from("<HH", data, 28 + 4 * i) for i in range(count))
    at, events = start + 32 + size, []
    while True:
        try:
            pcr, kind, digests = struct.unpack_from("<III", dump, at)
        except struct.error:
            break
        if digests != len(banks) or pcr > 23:
            break
        p, seen = at + 12, {}
        for _ in range(digests):
            bank, = struct.unpack_from("<H", dump, p)
            if bank not in banks or bank in seen:
                break
            seen[bank] = dump[p + 2:p + 2 + banks[bank]]
            p += 2 + banks[bank]
        if len(seen) != len(banks):
            break
        length, = struct.unpack_from("<I", dump, p)
        if length > 1 << 20:
            break
        events.append((pcr, kind, seen, dump[p + 4:p + 4 + length]))
        at = p + 4 + length
    return at - start, banks, events

found = []
at = dump.find(SPEC)
while at != -1:
    walked = walk(at - 32)
    if walked and walked[0] == want:
        found.append((at - 32, walked))
    at = dump.find(SPEC, at + 1)
if not found:
    sys.exit(f"no copy of {want} bytes in the dump")
copies = {dump[start:start + want] for start, _ in found}
if len(copies) != 1:
    sys.exit(f"{len(found)} copies of {want} bytes, and they differ; nothing written")
start, (length, banks, events) = found[0]
open(out, "wb").write(dump[start:start + length])

pcrs, touched, folded = {i: bytearray(32) for i in range(24)}, set(), 0
for pcr, kind, digests, data in events:
    if pcr == 0 and kind == EV_EFI_HCRTM_EVENT:
        pcrs[0][31] = 4
    if pcr == 0 and kind == EV_NO_ACTION and data.startswith(b"StartupLocality\0"):
        pcrs[0][31] = data[16]
    if kind == EV_NO_ACTION:
        continue
    pcrs[pcr] = bytearray(hashlib.sha256(bytes(pcrs[pcr]) + digests[SHA256]).digest())
    touched.add(pcr)
    folded += 1

print(f"wrote {out}: {length} bytes at {start:#x} ({len(found)} identical copies in memory)")
print(f"banks {sorted(f'{b:#06x}:{s}' for b, s in banks.items())}; "
      f"{len(events)} events, {folded} folded; PCRs {sorted(touched)}")
for pcr in sorted(touched):
    print(f"  PCR {pcr:2} {bytes(pcrs[pcr]).hex()}")
PY
grep -aE "tpm            (PCR 8|log and TPM agree|log not checked|FAILED)|bhaskixboot: (event log|final events)" "$SERIAL" \
    | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g'
