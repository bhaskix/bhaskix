#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The native loader's lane -- RFC 0028, graduated on purpose.
#
# The LOADER-specific gates: the payload byte-verified against a second
# checksum implementation, the machine's shape taken, the kernel slid by
# a drawn KASLR slide the kernel itself confirms, the jump through the
# shim's second door, four CPUs online -- found in the MADT and started
# by the kernel's own INIT-SIPI, with no loader help -- and the permanent
# negative arm. Full-system parity lives next door: `boot-test.sh native`
# runs the SAME gate list every Limine lane runs, which is what closed
# the roadmap's bhaskixboot bullet (RFC 0028 step 7).
#
# Usage:
#   tests/qemu/native-boot-test.sh

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
KERNEL="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
INITRD="$REPO_ROOT/build/initrd.tar"
LOG="${BHASKIX_NATIVE_BOOT_LOG:-$(mktemp)}"
# The second UART's log. **The SR550's service processor carries COM2, not
# COM1** -- found by the kernel on 2026-08-23 -- and the loader wrote COM1 only
# until 2026-10-08, so on that machine everything it wrote after its banner went
# to a port nobody read. The main boot gives QEMU a COM2 so the gates below can
# ask it what the loader said.
COM2_LOG="$(mktemp)"
TIMEOUT=60

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
    # **Unless a skip would be a lie** (2026-10-11): CI sets `BHASKIX_REQUIRE=1`,
    # because a job that exists to run this lane and skips it is green while
    # testing nothing.
    if [[ "${BHASKIX_REQUIRE:-0}" == 1 ]]; then
        fail "OVMF is not installed, and this run requires the native lane"
        exit 1
    fi
    printf '%sskip%s  native boot test (OVMF not installed)\n' "$YELLOW" "$RESET"
    exit 0
fi

# The ESP as a directory: QEMU's fat: driver serves it read-write, no image
# tooling needed, and EFI/BOOT/BOOTX64.EFI is the removable-media path every
# firmware falls back to.
# **A TPM on request** -- `BHASKIX_TPM=1`, RFC 0089. The emulator runs in a
# container from `tools/swtpm.sh`, and a fresh one is started before each boot:
# a TPM is state, and the second boot below must not inherit the first's PCRs.
TPM_ARGS=()
TPM_DIR="$REPO_ROOT/build/swtpm-native"
stop_tpm() { :; }
start_tpm() { :; }
if [[ "${BHASKIX_TPM:-0}" == 1 ]]; then
    # No container runtime, no emulator: said, as a missing OVMF is above,
    # rather than failed -- the lane cannot run here, and that is a fact about
    # the machine, not the loader.
    if ! docker info >/dev/null 2>&1; then
        if [[ "${BHASKIX_REQUIRE:-0}" == 1 ]]; then
            fail "no usable docker for tools/swtpm.sh, and this run requires the TPM lane"
            exit 1
        fi
        printf '%sskip%s  native boot test with a TPM (no usable docker for tools/swtpm.sh)\n' "$YELLOW" "$RESET"
        exit 0
    fi
    # shellcheck source=tests/qemu/devices.sh
    source "$REPO_ROOT/tests/qemu/devices.sh"
    stop_tpm() { "$REPO_ROOT/tools/swtpm.sh" stop "$TPM_DIR"; }
    start_tpm() {
        stop_tpm
        "$REPO_ROOT/tools/swtpm.sh" start "$TPM_DIR" || { fail "the TPM emulator did not start"; exit 1; }
    }
    trap stop_tpm EXIT
    qemu_tpm_args "$TPM_DIR/swtpm.sock"
fi

ESP="$REPO_ROOT/build/native-esp"
rm -rf "$ESP"
mkdir -p "$ESP/EFI/BOOT" "$ESP/bhaskix"
cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
# The payload, staged where the loader's fixed paths expect it. The
# configuration is one line today; it becomes the command line at the
# entry step.
cp "$KERNEL" "$ESP/bhaskix/kernel"
cp "$INITRD" "$ESP/bhaskix/initrd.tar"
# **`kaslr=show`, and it is load-bearing for the gate below.** RFC 0042 stopped
# the boot report printing the slide, because the report is about to be readable
# from ring 3 and the slide is the one secret in it. But the check that makes
# KASLR *real* on this lane is that the kernel names the same number the loader
# drew -- and it cannot be checked against a number nobody prints.
#
# So this lane asks for it. That is not a hole: a machine somebody can hand a
# command line to is a machine they already control, which is the same reasoning
# `iommu=off` rests on.
printf 'cmdline=kaslr=show\n' > "$ESP/bhaskix/boot.conf"

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

# -cpu max for RDRAND: the slide gates below demand a drawn slide, and the
# default model has no entropy to draw from. The entropy-less path stays
# legal (RFC 0021) but this lane's job is to prove the slid one.
echo "booting the native loader under $(basename "$OVMF_CODE"), up to ${TIMEOUT}s..."
start_tpm
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -cpu max -smp 4 -m 256 -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    "${TPM_ARGS[@]}" \
    -serial "file:$LOG" \
    -serial "file:$COM2_LOG" \
    >/dev/null 2>&1 &
QEMU_PID=$!

# Poll for the last expected line rather than waiting the whole timeout:
# the loader returns to the firmware after speaking, and the firmware then
# wanders into its own shell -- the output is the event, not the exit.
# **The last expected line moved on 2026-10-08**, from the TLB shootdown
# report to RFC 0089's `tpm` line, which the kernel prints after PCI comes
# up: a lane that stopped at the shootdown never saw it. With a CRB TPM the
# last line is `bin/tpmd`'s answer, or its failure -- not the discovery line
# before it (step 5c). **And again on 2026-10-11** (step 6): the replay's
# verdict follows the PCR line, so a lane that stopped at the PCR line could
# miss it. The verdict is printed after every PCR outcome, failures included;
# only a `bin/tpmd` that never started has no verdict, and says `FAILED to`.
# The replay's verdict line, colour stripped -- RFC 0089 step 6.
verdict_of() {
    grep -aE "tpm            (log and TPM agree|log not checked|FAILED: the log|FAILED: bin/tpmd never answered the replay|FAILED: the replay)" "$1" 2>/dev/null \
        | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g; s/^ *tpm *//' | head -1
}
# The PCRs a set names, one per line: `0-4, 6-9` -> 0 1 2 3 4 6 7 8 9.
pcrs_in() {
    local part parts
    IFS=',' read -ra parts <<< "$1"
    for part in "${parts[@]}"; do
        part="${part// /}"
        if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            seq "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            echo "$part"
        fi
    done
}
# Whether verdict "$1" is an agreement naming every PCR after it.
agrees_on() {
    local re='^log and TPM agree on PCRs? ([0-9, -]+): ([1-9][0-9]*) events replayed \(sha256\), in bin/tpmd$'
    [[ "$1" =~ $re ]] || return 1
    local named pcr
    named=" $(pcrs_in "${BASH_REMATCH[1]}" | tr '\n' ' ')"
    shift
    for pcr in "$@"; do
        [[ "$named" == *" $pcr "* ]] || return 1
    done
}
TPM_LAST="tpm            (log and TPM agree|log not checked|FAILED: the log|FAILED: bin/tpmd never answered the replay|FAILED: the replay|FAILED to |no TPM2 table|start method|no ACPI)"
for _ in $(seq 1 "$TIMEOUT"); do
    if grep -qE "$TPM_LAST|bhaskixboot: (the exit was refused|the exit succeeded with an empty|the table pool ran dry|payload .* REFUSED|the kernel image failed)" "$LOG" 2>/dev/null; then
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

# RFC 0089 step 2: **measured, or saying it was not.** With a TPM the loader
# must report all three objects measured and none refused; without one it must
# say nothing was measured -- an unmeasured boot that kept quiet would read, to
# anyone looking later, like a measured boot that found nothing wrong.
if [[ "${BHASKIX_TPM:-0}" == 1 ]]; then
    measured=0
    for object in "kernel into PCR 9" "initrd into PCR 9" "cmdline into PCR 8"; do
        grep -qF "bhaskixboot: measured $object" "$LOG" 2>/dev/null && measured=$((measured + 1))
    done
    if [[ $measured -eq 3 ]] && ! grep -qF "REFUSED, status" "$LOG"; then
        pass "the loader measured the kernel, the initrd and the command line through the firmware's TPM"
    else
        fail "the loader measured $measured of 3 objects: $(grep -aE 'bhaskixboot: (measure|no TCG2)' "$LOG" | tr -d '\r' | tr '\n' ' ')"
        status=1
    fi
else
    if grep -qF "bhaskixboot: no TCG2 protocol; nothing is measured" "$LOG" 2>/dev/null; then
        pass "with no TPM the loader said nothing was measured"
    else
        fail "with no TPM the loader did not say it measured nothing"
        status=1
    fi
fi

# RFC 0089 step 6: **the log the kernel gets is the whole log.** The copy is
# taken at `GetEventLog`; the firmware logs what comes after -- its own two
# `ExitBootServices` events into PCR 5 -- in its final events table, which the
# loader appends after the exit. Without them a replay of PCR 5 cannot agree.
# With no TPM there is no log, and the line must not appear.
if [[ "${BHASKIX_TPM:-0}" == 1 ]]; then
    final=$(grep -aoE "bhaskixboot: final events [0-9]+ \([0-9]+ bytes\) appended after the exit" "$LOG" | head -1)
    if [[ "$final" =~ final\ events\ ([0-9]+) ]] && [[ ${BASH_REMATCH[1]} -ge 2 ]] \
        && ! grep -qF "final events not all carried" "$LOG"; then
        pass "the loader appended the firmware's final events after the exit (${final#bhaskixboot: })"
    else
        fail "the final events were not carried: $(grep -aE 'bhaskixboot: final events' "$LOG" | tr -d '\r' | tr '\n' ' ')"
        status=1
    fi
elif grep -qF "bhaskixboot: final events" "$LOG" 2>/dev/null; then
    fail "with no TPM the loader still spoke of final events"
    status=1
else
    pass "with no TPM the loader carried no final events"
fi

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
# The slide, drawn fresh every boot: extracted from the loader's own line,
# then checked against the policy (2 MiB aligned, inside (0, 1 GiB)) and,
# below, against the kernel's independent measurement of it.
SLIDE=$(grep -oE "bhaskixboot: relative relocations applied: $KRELOCS, slide 0x[0-9a-f]{16}" "$LOG" 2>/dev/null | grep -oE '0x[0-9a-f]{16}$' || true)
if [ -n "$SLIDE" ]; then
    pass "all $KRELOCS relative relocations applied at slide $SLIDE"
else
    fail "relocation line missing or wrong: wanted $KRELOCS relocations"
    status=1
    SLIDE=0x0
fi
if python3 -c "
s = int('$SLIDE', 16)
raise SystemExit(0 if (s != 0 and s % (2 << 20) == 0 and s < (1 << 30)) else 1)
"; then
    pass "the slide obeys the policy: nonzero, 2 MiB aligned, under 1 GiB"
else
    fail "the slide $SLIDE breaks the policy (nonzero, 2 MiB aligned, under 1 GiB)"
    status=1
fi
SLID_ENTRY=$(python3 -c "import sys; print('0x%016x' % ((int(sys.argv[1], 16) + int(sys.argv[2], 16)) & ((1 << 64) - 1)))" "$KENTRY" "$SLIDE")
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
# **The pool is sized from the machine** (2026-10-08). A fixed 128 frames ran
# dry on an SR550 with 192 GiB, after the exit. The loader now sets aside the
# bound `bhaskix-boot` computes from the map and says so; the gate holds what
# it used to what it set aside, and a guest this size to a small pool -- a
# bound that grew without reason would be caught here, not on a server.
pool_line="$(grep -aE 'bhaskixboot: table pool [0-9]+ frames for memory to 0x[0-9a-f]{16}' "$LOG" | tr -d '\r' | head -1)"
used_line="$(grep -aE 'bhaskixboot: tables built: [0-9]+ frames' "$LOG" | tr -d '\r' | head -1)"
pool_frames="$(sed -E 's/.*table pool ([0-9]+) frames.*/\1/' <<< "$pool_line")"
used_frames="$(sed -E 's/.*tables built: ([0-9]+) frames.*/\1/' <<< "$used_line")"
if [[ -n "$pool_line" && -n "$used_line" ]] && (( used_frames <= pool_frames && pool_frames <= 32 )); then
    pass "the table pool was sized from the map: $pool_frames frames set aside, $used_frames used"
else
    fail "the table pool: '${pool_line:-no pool line}', '${used_line:-no table line}'"
    status=1
fi
# **On every CPU, read back from its own registers** (2026-10-08). The line
# above is the bootstrap CPU's, and it was the only thing anyone checked:
# QEMU's monitor showed every secondary with SMEP and SMAP off on both boot
# paths, and with WP off under the native loader, while that line said "on".
# Each CPU now enables them for itself and counts itself only if it reads them
# back; this holds the count to the CPUs online. On `-cpu qemu64`, which has
# neither SMEP nor SMAP, WP is still required on every CPU.
protections_line="$(grep -aE 'supervisor +(wp, and smep|FAILED: wp)' "$LOG" | tr -d '\r' | head -1)"
online_cpus="$(grep -aE 'cpus +[0-9]+ online of' "$LOG" | tr -d '\r' | head -1 | sed -E 's/.*cpus +([0-9]+) online.*/\1/')"
if [[ "$protections_line" =~ live\ on\ ([0-9]+)\ of\ ([0-9]+)\ cpus ]] \
    && [[ "$protections_line" != *FAILED* ]] \
    && [[ "${BASH_REMATCH[1]}" == "${BASH_REMATCH[2]}" && "${BASH_REMATCH[2]}" == "$online_cpus" ]]; then
    pass "wp, smep and smap live on every cpu: ${BASH_REMATCH[1]} of $online_cpus"
else
    fail "supervisor protections on every cpu: '${protections_line:-no line}', ${online_cpus:-?} online"
    status=1
fi
INITRD_BYTES2=$(stat -c %s "$ESP/bhaskix/initrd.tar")
if grep -qE "bhaskixboot: handoff assembled: version 3, [1-9][0-9]* regions, initrd $INITRD_BYTES2 bytes, stack top 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the handoff is assembled: version 3, the initrd whole"
else
    fail "handoff line missing or wrong"
    status=1
fi
if grep -qE "bhaskixboot: the world is built; jumping: entry $SLID_ENTRY, cr3 0x[0-9a-f]{16}, handoff 0x[0-9a-f]{16}" "$LOG" 2>/dev/null; then
    pass "the world is built, and the loader jumped to the ELF's entry plus the slide"
else
    fail "the jump line never appeared, or its entry is not $KENTRY + $SLIDE"
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
if grep -qF "handoff version 3" "$LOG" 2>/dev/null; then
    pass "the kernel validated and accepted the handoff the loader built"
else
    fail "the kernel never reported the handoff"
    status=1
fi

# **COM2 carries the loader too** (2026-10-08). The banner is written before
# the firmware's serial port is adopted, and the lines from the exit on after
# it is released; both go to every UART that answers. The lines between go
# through the firmware's own port -- COM1 under OVMF -- and **must not** reach
# COM2, because writing a UART's registers underneath the firmware's driver is
# what UEFI §12 provides a protocol to avoid: a payload line here would mean the
# loader bypassed it. The kernel's report follows, as it does on the SR550.
com2_missing=""
for want in "bhaskixboot 0.0.0: the machine entered through our own door" \
            "bhaskixboot: boot services exited; the machine is ours" \
            "bhaskixboot: the world is built; jumping" \
            "An open-source, AI-native, enterprise operating system"; do
    grep -qF "$want" "$COM2_LOG" 2>/dev/null || com2_missing="${com2_missing:+$com2_missing; }$want"
done
if [[ -z "$com2_missing" ]]; then
    pass "COM2 carries the loader's banner, its lines after the exit, and the kernel's report"
else
    fail "COM2 is missing: $com2_missing"
    status=1
fi
# The kernel's checksum too: until 2026-10-08 the number writers wrote the
# registers directly while the text around them went through the protocol, so a
# bypass shows as a bare number with no words beside it.
if grep -qF "bhaskixboot: payload kernel" "$COM2_LOG" 2>/dev/null \
    || grep -qF "$KERNEL_FNV" "$COM2_LOG" 2>/dev/null; then
    fail "COM2 carries a line or a number from inside boot services: the loader wrote under the firmware's driver"
    status=1
else
    pass "nothing from inside boot services reached COM2 directly"
fi

# RFC 0089 step 3: **the log reached the kernel, and the kernel read it.** With a
# TPM, the loader copied the whole log and the kernel found the loader's three
# events in it, by tag and PCR, each with a SHA-256; without one, the kernel
# says nothing was recorded.
MEASURED_DIGESTS=""
PCRS=""
if [[ "${BHASKIX_TPM:-0}" == 1 ]]; then
    line="$(grep -aE 'measured boot   kernel' "$LOG" | tr -d '\r' | head -1)"
    if [[ "$line" =~ kernel\ ([0-9a-f]{8})\ initrd\ ([0-9a-f]{8})\ cmdline\ ([0-9a-f]{8})\ \(sha256,\ PCR\ 9/9/8\)\;\ [1-9][0-9]*\ events,\ log\ complete ]] \
        && grep -qE "bhaskixboot: event log [1-9][0-9]* bytes copied, truncated by the firmware: no" "$LOG" \
        && ! grep -qF "the log stops parsing" "$LOG"; then
        MEASURED_DIGESTS="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
        pass "the kernel read the loader's three measurements out of the event log: ${line#*measured boot   }"
    else
        fail "the kernel did not read the three measurements from the log: ${line:-no measured boot line}"
        status=1
    fi
elif grep -qF "measured boot   no TPM: the firmware has no TCG2 protocol" "$LOG" 2>/dev/null; then
    pass "with no TPM the kernel said nothing was recorded"
else
    fail "with no TPM the kernel did not say nothing was recorded"
    status=1
fi

# RFC 0089 step 5a: **the TPM the firmware measured into is one the kernel can
# find.** With the emulated TPM, the ACPI `TPM2` table names a CRB interface;
# without it, there is no table.
if [[ "${BHASKIX_TPM:-0}" == 1 ]]; then
    if grep -qE "tpm            CRB at 0x[0-9a-f]+ \(ACPI TPM2, start method 7\)" "$LOG" 2>/dev/null; then
        pass "the kernel found the TPM through ACPI: $(grep -aoE 'CRB at 0x[0-9a-f]+' "$LOG" | head -1)"
    else
        fail "the kernel did not find a CRB TPM through ACPI: $(grep -aE '^ *tpm  ' "$LOG" | tr -d '\r' | head -1)"
        status=1
    fi
    # RFC 0089 step 5c: **the TPM itself, asked.** `bin/tpmd`, in a domain
    # holding one register page, read PCRs 8 and 9 and the kernel printed them.
    PCR_LINE="$(grep -aE 'tpm            PCR 8 ' "$LOG" | tr -d '\r' | head -1)"
    if [[ "$PCR_LINE" =~ PCR\ 8\ ([0-9a-f]{8})\ PCR\ 9\ ([0-9a-f]{8})\ \(sha256\),\ read\ through\ bin/tpmd ]] \
        && [[ "${BASH_REMATCH[1]}" != 00000000 && "${BASH_REMATCH[2]}" != 00000000 ]]; then
        PCRS="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
        pass "bin/tpmd read the TPM's own PCRs: ${PCR_LINE#*tpm            }"
    else
        fail "bin/tpmd did not read PCRs 8 and 9: $(grep -aE '^ *tpm  ' "$LOG" | tr -d '\r' | tail -2 | tr '\n' ' ')"
        status=1
    fi
    # RFC 0089 step 6: **the log and the TPM agree.** `bin/tpmd` replayed the
    # whole log with the tree's SHA-256 and read every PCR it touched. Which
    # PCRs the firmware extends is the firmware's business; the gate demands 5
    # -- `ExitBootServices`' own, carried only in the final events table --
    # and 8 and 9, the loader's.
    if agrees_on "$(verdict_of "$LOG")" 5 8 9; then
        pass "the log, replayed, agrees with the TPM: $(verdict_of "$LOG")"
    else
        fail "the log and the TPM were not shown to agree: '$(verdict_of "$LOG")'"
        status=1
    fi
elif grep -qF "tpm            no TPM2 table" "$LOG" 2>/dev/null; then
    if grep -qF "log and TPM agree" "$LOG"; then
        fail "with no TPM the kernel still claimed the log and a TPM agree"
        status=1
    else
        pass "with no TPM the kernel found no TPM2 table, and claimed no agreement"
    fi
else
    fail "with no TPM the kernel did not say there is no TPM2 table"
    status=1
fi
# The cross-check that makes the slide real: the kernel computes it
# independently, from the handoff's virt base against its own link base,
# and must name the same number the loader drew.
KERNEL_SLIDE=$(python3 -c "print(hex(int('$SLIDE', 16)))")
if grep -qE "kaslr +slid $KERNEL_SLIDE bytes from 0xffffffff80000000" "$LOG" 2>/dev/null; then
    pass "the kernel measured the slide itself and named the loader's number"
else
    fail "the kernel did not report slide $KERNEL_SLIDE (unslid, or a different number)"
    status=1
fi
# The secondaries: the loader still offers nothing, and the kernel now
# does it alone -- discovery from the MADT, the trampoline, INIT-SIPI.
if grep -qF "INIT-SIPI from the kernel: 4 processors in the madt" "$LOG" 2>/dev/null; then
    pass "the kernel found four processors in the madt and started them itself"
else
    fail "the kernel's INIT-SIPI line never appeared, or the count is not 4"
    status=1
fi
if grep -qE "cpus +4 online of 4 reported" "$LOG" 2>/dev/null; then
    pass "all four CPUs are online, none missing, none invented"
else
    fail "the cpus line is missing or short of 4 online of 4"
    status=1
fi
if grep -qE "tlb shootdown +[1-9][0-9]* completed across 4 cpus, none timed out" "$LOG" 2>/dev/null; then
    pass "shootdown IPIs cross all four natively-started CPUs"
else
    fail "the shootdown line is missing, timed out, or short of 4 cpus"
    status=1
fi

# The negative arm, permanent: a corrupted kernel image must be refused
# with its reason printed, never jumped into. The corruption is the ELF
# magic -- the parser's first check -- and the arm demands both the refusal
# and the absence of any jump.
echo "the negative arm: a corrupted kernel must be refused, up to ${TIMEOUT}s..."
printf 'XXXX' | dd of="$ESP/bhaskix/kernel" bs=1 count=4 conv=notrunc 2>/dev/null
# **Put it back on the way out, whatever happens.** The corruption above is
# deliberate and the refusal it proves is worth having; leaving it behind is
# not. This directory is a staged ESP, and it is the obvious thing to build
# real boot media from -- which somebody did on 2026-08-22, imaged a kernel
# with its ELF magic destroyed, and spent a while establishing that the loader
# was right and the medium was wrong. A trap that only springs outside the
# test that set it is the worst kind.
restore_kernel() { cp "$KERNEL" "$ESP/bhaskix/kernel" 2>/dev/null; }
# One more boot of the ESP as it now stands, with a fresh TPM, to the verdict
# line or the timeout; its serial output goes to "$1".
tpm_boot() {
    cp "$OVMF_VARS" "$WRITABLE_VARS"
    start_tpm
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -machine q35 -cpu max -smp 4 -m 256 -display none \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
        -drive "format=raw,file=fat:rw:$ESP" \
        "${TPM_ARGS[@]}" \
        -serial "file:$1" \
        >/dev/null 2>&1 &
    local pid=$!
    for _ in $(seq 1 "$TIMEOUT"); do
        grep -qE "$TPM_LAST" "$1" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}
trap 'restore_kernel; stop_tpm' EXIT
cp "$OVMF_VARS" "$WRITABLE_VARS"
NEGATIVE_LOG=$(mktemp)
start_tpm
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 256 -display none \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS" \
    -drive "format=raw,file=fat:rw:$ESP" \
    "${TPM_ARGS[@]}" \
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

# RFC 0089 step 3's gate, the one step 2 could not have: **the kernel's digest
# follows the kernel's bytes.** One byte flipped inside `.debug_info` -- in the
# file, never loaded, so the kernel still boots -- must change the PCR 9 digest
# the log carries for the kernel and leave the initrd's and the command line's
# alone. The offset is the section's own, read from the ELF's section headers.
if [[ "${BHASKIX_TPM:-0}" == 1 && -n "$MEASURED_DIGESTS" ]]; then
    restore_kernel
    if python3 - "$ESP/bhaskix/kernel" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
shoff, = struct.unpack_from("<Q", data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
def section(i):
    base = shoff + i * shentsize
    name, = struct.unpack_from("<I", data, base)
    offset, size = struct.unpack_from("<QQ", data, base + 0x18)
    return name, offset, size
_, names_at, _ = section(shstrndx)
for i in range(shnum):
    name, offset, size = section(i)
    end = data.index(b"\0", names_at + name)
    if data[names_at + name:end] == b".debug_info" and size > 0:
        data[offset + size // 2] ^= 0xFF
        open(path, "wb").write(data)
        sys.exit(0)
sys.exit(1)
PY
    then
        echo "the digest arm: one kernel byte flipped, up to ${TIMEOUT}s..."
        FLIPPED_LOG=$(mktemp)
        tpm_boot "$FLIPPED_LOG"
        restore_kernel
        flipped="$(grep -aE 'measured boot   kernel' "$FLIPPED_LOG" | tr -d '\r' | head -1)"
        read -r k0 i0 c0 <<< "$MEASURED_DIGESTS"
        if [[ "$flipped" =~ kernel\ ([0-9a-f]{8})\ initrd\ ([0-9a-f]{8})\ cmdline\ ([0-9a-f]{8}) ]] \
            && [[ "${BASH_REMATCH[1]}" != "$k0" && "${BASH_REMATCH[2]}" == "$i0" && "${BASH_REMATCH[3]}" == "$c0" ]]; then
            pass "one flipped kernel byte changed its PCR 9 digest ($k0 -> ${BASH_REMATCH[1]}) and nothing else's"
        else
            fail "a flipped kernel byte gave '${flipped:-no measured line}' against $MEASURED_DIGESTS"
            status=1
        fi
        # And the TPM agrees: its PCR 9 moved and its PCR 8 did not.
        flipped_pcrs="$(grep -aE 'tpm            PCR 8 ' "$FLIPPED_LOG" | tr -d '\r' | head -1)"
        read -r p8 p9 <<< "${PCRS:-- -}"
        if [[ "$flipped_pcrs" =~ PCR\ 8\ ([0-9a-f]{8})\ PCR\ 9\ ([0-9a-f]{8}) ]] \
            && [[ "${BASH_REMATCH[1]}" == "$p8" && "${BASH_REMATCH[2]}" != "$p9" ]]; then
            pass "the TPM agrees: PCR 9 moved ($p9 -> ${BASH_REMATCH[2]}) and PCR 8 did not"
        else
            fail "the TPM's PCRs after a flipped kernel byte: '${flipped_pcrs:-no PCR line}' against PCR 8 $p8, PCR 9 $p9"
            status=1
        fi
        # Step 6: and the log still agrees with it -- a changed kernel boots
        # *recorded*, which is the whole of what this RFC promises.
        if agrees_on "$(verdict_of "$FLIPPED_LOG")" 5 8 9; then
            pass "with the kernel changed, the log still agrees with the TPM: it recorded the change"
        else
            fail "after a flipped kernel byte the verdict was '$(verdict_of "$FLIPPED_LOG")'"
            status=1
        fi

        # Step 6's red line, which needs a boot where the two do not agree:
        # `bhaskix.fault=tpm-log` flips one byte of the kernel's digest in the
        # copy `bin/tpmd` replays, and nothing the TPM holds. The disagreement
        # must be named, and be PCR 9's alone -- the command line's extra word
        # moves PCR 8, but in the log as well as the TPM.
        echo "the replay arm: a log that lies about the kernel, up to ${TIMEOUT}s..."
        LYING_LOG=$(mktemp)
        printf 'cmdline=kaslr=show bhaskix.fault=tpm-log\n' > "$ESP/bhaskix/boot.conf"
        tpm_boot "$LYING_LOG"
        printf 'cmdline=kaslr=show\n' > "$ESP/bhaskix/boot.conf"
        lying="$(verdict_of "$LYING_LOG")"
        lying_re='^FAILED: the log and the TPM disagree on PCR 9 \(agree on ([0-9, -]+)\)$'
        if grep -qF "fault injection: one byte of the kernel's digest flipped" "$LYING_LOG" \
            && [[ "$lying" =~ $lying_re ]] \
            && [[ " $(pcrs_in "${BASH_REMATCH[1]}" | tr '\n' ' ')" == *" 5 "*" 8 "* ]]; then
            pass "a log that lies about the kernel is caught: $lying"
        else
            fail "a log with the kernel's digest flipped gave '${lying:-no verdict}'"
            status=1
        fi
        rm -f "$LYING_LOG"
    else
        fail "the kernel image has no .debug_info section to flip a byte in"
        status=1
    fi
fi

if [[ "$status" -ne 0 ]]; then
    echo "--- serial log ---"
    cat "$LOG" 2>/dev/null | head -60
    # The byte count first: an empty file and one missing a line are different
    # failures, and the head of an empty file looks like no output at all.
    echo "--- COM2 log ($(wc -c < "$COM2_LOG" 2>/dev/null || echo 'no file,') bytes) ---"
    head -20 "$COM2_LOG" 2>/dev/null
fi
rm -f "$COM2_LOG"
exit "$status"
