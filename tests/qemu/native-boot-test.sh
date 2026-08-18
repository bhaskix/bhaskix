#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The native loader's lane -- RFC 0028, graduated on purpose.
#
# This script's gate list IS the honest statement of how far sovereignty
# has come: it grows a check per implemented step, and the roadmap's
# bhaskixboot bullet closes only when this lane runs the same gates the
# Limine lanes do. Today it proves step 1: the firmware starts our loader,
# and the first words on the serial wire are ours.
#
# Usage:
#   tests/qemu/native-boot-test.sh

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
LOG="${BHASKIX_NATIVE_BOOT_LOG:-$(mktemp)}"
TIMEOUT=30

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'

pass() { printf '%sok%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$1"; }

if [[ ! -f "$LOADER" ]]; then
    fail "bhaskixboot.efi is not built; make it first"
    exit 1
fi
if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
    fail "the payload (kernel, initrd) is not built; make iso first"
    exit 1
fi

# OVMF ships as a CODE/VARS pair and must be searched as one -- the same
# rule, and the same pair list, as boot-test.sh's uefi mode, for the same
# recorded reasons.
OVMF_CODE=""
OVMF_VARS=""
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd" \
    "/usr/share/qemu/OVMF_CODE.fd:/usr/share/qemu/OVMF_VARS.fd"
do
    code="${pair%%:*}"
    vars="${pair##*:}"
    if [[ -f "$code" && -f "$vars" ]]; then
        OVMF_CODE="$code"
        OVMF_VARS="$vars"
        break
    fi
done
if [[ -z "$OVMF_CODE" ]]; then
    if compgen -G "/usr/share/OVMF/*.fd" >/dev/null 2>&1 \
       || compgen -G "/usr/share/edk2/ovmf/*.fd" >/dev/null 2>&1; then
        fail "OVMF is installed but no complete CODE/VARS pair was found"
        exit 1
    fi
    printf '%sskip%s  native boot test (OVMF not installed)\n' "$YELLOW" "$RESET"
    exit 0
fi

# The ESP as a directory: QEMU's fat: driver serves it read-write, no image
# tooling needed, and EFI/BOOT/BOOTX64.EFI is the removable-media path every
# firmware falls back to.
ESP="$REPO_ROOT/build/native-esp"
rm -rf "$ESP"
mkdir -p "$ESP/EFI/BOOT" "$ESP/bhaskix"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
# The payload, staged where the loader's fixed paths expect it. The
# configuration is one line today; it becomes the command line at the
# entry step.
cp "$KERNEL" "$ESP/bhaskix/kernel"
cp "$INITRD" "$ESP/bhaskix/initrd.tar"
printf 'cmdline=\n' > "$ESP/bhaskix/boot.conf"

# The build's own checksums, computed independently of the loader by the
# same stated arithmetic (FNV-1a 64), so the gate is two implementations
# agreeing about the same bytes -- not the loader agreeing with itself.
fnv() {
    python3 - "$1" <<'PY'
import sys
h = 0xcbf29ce484222325
with open(sys.argv[1], "rb") as f:
    while chunk := f.read(65536):
        for b in chunk:
            h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
print(f"0x{h:016x}")
PY
}
KERNEL_BYTES=$(stat -c %s "$ESP/bhaskix/kernel")
KERNEL_FNV=$(fnv "$ESP/bhaskix/kernel")
INITRD_BYTES=$(stat -c %s "$ESP/bhaskix/initrd.tar")
INITRD_FNV=$(fnv "$ESP/bhaskix/initrd.tar")
CONF_BYTES=$(stat -c %s "$ESP/bhaskix/boot.conf")
CONF_FNV=$(fnv "$ESP/bhaskix/boot.conf")

# The kernel image's own facts, from a second ELF reader: loadable segment
# count, entry point, link base, and how many relative relocations the
# dynamic table names. The loader must agree exactly with all four.
read -r KSEGS KENTRY KBASE KRELOCS <<< "$(python3 - "$ESP/bhaskix/kernel" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
entry = struct.unpack_from("<Q", data, 24)[0]
phoff = struct.unpack_from("<Q", data, 32)[0]
phentsize = struct.unpack_from("<H", data, 54)[0]
phnum = struct.unpack_from("<H", data, 56)[0]
segs, base, dyn = 0, None, None
loads = []
for i in range(phnum):
    o = phoff + i * phentsize
    p_type = struct.unpack_from("<I", data, o)[0]
    p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
    p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
    if p_type == 1:
        segs += 1
        loads.append((p_vaddr, p_offset, p_filesz))
        base = p_vaddr & ~0xFFF if base is None else min(base, p_vaddr & ~0xFFF)
    if p_type == 2:
        dyn = (p_offset, p_filesz)
relocs = 0
if dyn:
    rela = relasz = None
    at = dyn[0]
    while at + 16 <= dyn[0] + dyn[1]:
        tag, val = struct.unpack_from("<QQ", data, at)
        if tag == 0:
            break
        if tag == 7:
            rela = val
        if tag == 8:
            relasz = val
        at += 16
    if rela is not None and relasz:
        relocs = relasz // 24
print(f"{segs} 0x{entry:016x} 0x{base:016x} {relocs}")
PY
)"

WRITABLE_VARS="$REPO_ROOT/build/OVMF_VARS_native.fd"
cp "$OVMF_VARS" "$WRITABLE_VARS"

echo "booting the native loader under $(basename "$OVMF_CODE"), up to ${TIMEOUT}s..."
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 256 -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -serial "file:$LOG" \
    >/dev/null 2>&1 &
QEMU_PID=$!

# Poll for the last expected line rather than waiting the whole timeout:
# the loader returns to the firmware after speaking, and the firmware then
# wanders into its own shell -- the output is the event, not the exit.
for _ in $(seq 1 "$TIMEOUT"); do
    if grep -qE "handoff version 2|bhaskixboot: (the exit was refused|the exit succeeded with an empty|the table pool ran dry|payload .* REFUSED|the kernel image failed)" "$LOG" 2>/dev/null; then
        break
    fi
    sleep 1
done
kill "$QEMU_PID" >/dev/null 2>&1
wait "$QEMU_PID" 2>/dev/null

status=0
if grep -q "bhaskixboot 0.0.0: the machine entered through our own door" "$LOG" 2>/dev/null; then
    pass "the firmware started our loader, and the first words on the wire were ours"
else
    fail "the native loader's banner never appeared"
    status=1
fi

# Step 2: the payload's integrity, byte for byte. The loader streamed each
# file through FNV-1a and printed size and sum; the lines below were
# computed here, from the staged files, by a second implementation of the
# same arithmetic. Equality means the firmware served the build's bytes.
for check in     "kernel $KERNEL_BYTES bytes fnv $KERNEL_FNV"     "initrd $INITRD_BYTES bytes fnv $INITRD_FNV"     "conf $CONF_BYTES bytes fnv $CONF_FNV"
do
    if grep -qF "bhaskixboot: payload $check" "$LOG" 2>/dev/null; then
        pass "payload verified: $check"
    else
        fail "payload line missing or wrong: wanted '$check'"
        status=1
    fi
done

# Step 3: the machine's shape, and the exit. The values are the firmware's
# to choose -- the gates demand the *lines*, well-formed, plus the two facts
# that must be true on OVMF: an RSDP exists, and the map was not truncated.
if grep -qE "bhaskixboot: acpi rsdp 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the firmware's ACPI root was found and named"
else
    fail "no ACPI RSDP line"
    status=1
fi
if grep -qE "bhaskixboot: smbios (0x[0-9a-f]{16}|absent)" "$LOG" 2>/dev/null; then
    pass "SMBIOS found or its absence said"
else
    fail "no SMBIOS line"
    status=1
fi
if grep -qE "bhaskixboot: framebuffer [0-9]+x[0-9]+ stride [0-9]+ at 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the framebuffer was found and measured"
else
    fail "no framebuffer line"
    status=1
fi
if grep -qE "bhaskixboot: memory map [1-9][0-9]* descriptors, [1-9][0-9]* KiB usable, [0-9]+ KiB reclaimable; truncated: no" "$LOG" 2>/dev/null; then
    pass "the memory map was taken whole, nothing dropped"
else
    fail "no untruncated memory-map line"
    status=1
fi
if grep -qF "bhaskixboot: boot services exited; the machine is ours" "$LOG" 2>/dev/null; then
    pass "boot services exited: the machine is ours"
else
    fail "the exit line never appeared"
    status=1
fi

# Step 5: the load and the tables, every computable fact cross-checked
# against the second ELF reader above.
if grep -qF "bhaskixboot: kernel parsed: $KSEGS loadable segments, entry $KENTRY" "$LOG" 2>/dev/null; then
    pass "the kernel parsed: $KSEGS segments, entry $KENTRY, both agreed"
else
    fail "kernel parse line missing or wrong: wanted $KSEGS segments, entry $KENTRY"
    status=1
fi
if grep -qF "bhaskixboot: relative relocations applied: $KRELOCS, slide 0x0000000000000000" "$LOG" 2>/dev/null; then
    pass "all $KRELOCS relative relocations applied at slide zero"
else
    fail "relocation line missing or wrong: wanted $KRELOCS at slide zero"
    status=1
fi
if grep -qE "bhaskixboot: kernel placed at 0x[0-9a-f]{16}, virt base $KBASE, span [1-9][0-9]* KiB, W\^X per segment" "$LOG" 2>/dev/null; then
    pass "the kernel is placed at its link base, W^X per segment"
else
    fail "kernel placement line missing or wrong: wanted virt base $KBASE"
    status=1
fi
if grep -qE "bhaskixboot: tables built: [1-9][0-9]* frames; identity and hhdm to 0x[0-9a-f]{16}, kernel in the high half, cr3 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the world's tables stand: identity, hhdm, kernel high half"
else
    fail "table line missing or malformed"
    status=1
fi
INITRD_BYTES2=$(stat -c %s "$ESP/bhaskix/initrd.tar")
if grep -qE "bhaskixboot: handoff assembled: version 2, [1-9][0-9]* regions, initrd $INITRD_BYTES2 bytes, stack top 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the handoff is assembled: version 2, the initrd whole"
else
    fail "handoff line missing or wrong"
    status=1
fi
if grep -qE "bhaskixboot: the world is built; jumping: entry $KENTRY, cr3 0x[0-9a-f]{16}, handoff 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the world is built, and the loader jumped to the entry both readers named"
else
    fail "the jump line never appeared"
    status=1
fi

# Step 6: the kernel is running, entered through our own door. The words
# after the jump are the kernel's -- its banner, the loader named as ours
# in its own boot report, and its own validation of the handoff we built.
if grep -qF "An open-source, AI-native, enterprise operating system" "$LOG" 2>/dev/null; then
    pass "the kernel's banner followed the jump"
else
    fail "the kernel's banner never appeared after the jump"
    status=1
fi
if grep -qE "loader +bhaskixboot 0.0.0" "$LOG" 2>/dev/null; then
    pass "the kernel names bhaskixboot as its loader"
else
    fail "the kernel's loader line does not name bhaskixboot"
    status=1
fi
if grep -qF "handoff version 2" "$LOG" 2>/dev/null; then
    pass "the kernel validated and accepted the handoff the loader built"
else
    fail "the kernel never reported the handoff"
    status=1
fi
if grep -qF "loader reported no way to start secondaries" "$LOG" 2>/dev/null; then
    pass "the single-CPU reduction is stated by the kernel, not hidden"
else
    fail "the secondaries reduction was not stated"
    status=1
fi

# The negative arm, permanent: a corrupted kernel image must be refused
# with its reason printed, never jumped into. The corruption is the ELF
# magic -- the parser's first check -- and the arm demands both the refusal
# and the absence of any jump.
echo "the negative arm: a corrupted kernel must be refused, up to ${TIMEOUT}s..."
printf 'XXXX' | dd of="$ESP/bhaskix/kernel" bs=1 count=4 conv=notrunc 2>/dev/null
cp "$OVMF_VARS" "$WRITABLE_VARS"
NEGATIVE_LOG=$(mktemp)
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 256 -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    -serial "file:$NEGATIVE_LOG" \
    >/dev/null 2>&1 &
NEG_PID=$!
for _ in $(seq 1 "$TIMEOUT"); do
    if grep -q "bhaskixboot: the kernel image failed the parser" "$NEGATIVE_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
done
kill "$NEG_PID" >/dev/null 2>&1
wait "$NEG_PID" 2>/dev/null
if grep -q "bhaskixboot: the kernel image failed the parser" "$NEGATIVE_LOG" 2>/dev/null \
   && ! grep -q "jumping: entry" "$NEGATIVE_LOG" 2>/dev/null; then
    pass "a corrupted kernel was refused with its reason, and nothing jumped"
else
    fail "the corrupted kernel was not refused cleanly"
    status=1
    echo "--- negative-arm serial log ---"
    cat "$NEGATIVE_LOG" 2>/dev/null | head -20
fi

if [[ "$status" -ne 0 ]]; then
    echo "--- serial log ---"
    cat "$LOG" 2>/dev/null | head -60
fi
exit "$status"
