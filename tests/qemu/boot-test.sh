#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M1 exit criterion, as an executable check.
#
# Boots the ISO in QEMU, captures the serial console, and asserts the kernel
# reached the end of kernel_main without a fault. Used by `make test` and by CI.
#
#   tests/qemu/boot-test.sh bios
#   tests/qemu/boot-test.sh uefi
#
# Exits non-zero with the captured log on any failure.

set -uo pipefail

MODE="${1:-bios}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="$REPO_ROOT/build/bhaskix.iso"
# Overridable so a caller can keep the serial output. The test prints the log
# only when something fails, which is right for a gate and unhelpful when the
# thing you want is a number the machine measured.
LOG="${BHASKIX_BOOT_LOG:-$(mktemp)}"
TIMEOUT="${BOOT_TEST_TIMEOUT:-120}"

# One trap, doing both jobs. Two `trap ... EXIT` lines would not run in
# sequence: the second replaces the first, silently, and the temporary log
# would leak for every mode that also has an image to restore.
#
# The log is kept when the caller named it: they asked for it, so deleting it
# on the way out would be answering a different question.
restore_image() { :; }
cleanup() {
    restore_image
    [[ -n ${BHASKIX_BOOT_LOG:-} ]] || rm -f "$LOG"
}
trap cleanup EXIT

# The greeting is the milestone's contract. If you reword it, update
# docs/roadmap.md M1 and kernel/src/lib.rs::banner in the same change.
# The banner line that proves the console works. Changed when the boot banner
# gained the project's name in Devanagari and its author -- a greeting probe
# has to name a line that actually exists.
EXPECT_GREETING="the light-maker"

# Strings that mean the boot went wrong even if the greeting appeared.
FAILURE_MARKERS=("KERNEL PANIC" "FATAL:" "WARNING: the memory map was truncated"
                 "unexpected interrupt on vector" "NO TICKS"
                 "LEAK:" "INVARIANT VIOLATED"
                 # A program started without an address-space slot. The boot
                 # carries on and the damage lands somewhere else entirely: the
                 # program's faults cannot be serviced, so it never runs, and
                 # what gets reported is whatever was waiting on it. That is
                 # precisely how a leaked slot per ended domain read for six
                 # days as a broken block driver.
                 "address space  no free slot"
                 # **The instrument that hunts the wrong-`CR3` fault, made
                 # fatal.** Both lines were printed in red and neither failed a
                 # boot: a thread that reached ring 3 in somebody else's
                 # address space, and -- since 2026-08-20 -- one that reached it
                 # owning no space at all, which is the case the check skipped
                 # silently for a week while the fault it exists for was
                 # arriving in exactly that shape. A detector nobody fails on is
                 # a detector that reports into an empty room.
                 "exits to ring 3 held somebody else's space"
                 "exits to ring 3 owned no space at all"
                 # Every self-test the kernel runs reports failure with this
                 # word, and until 2026-08-11 nothing looked for it. A failure
                 # was caught only where a *positive* gate below asserted that
                 # test's success line, because the failure stopped the pattern
                 # matching -- so a self-test with no gate could fail with the
                 # suite green, and six of them could.
                 #
                 # This closes the class rather than the six. A new self-test
                 # now arrives gated by default: printing FAILED is enough.
                 #
                 # It does not make the positive gates redundant, and they are
                 # kept. This catches a test that ran and failed; a positive
                 # gate also catches one that never ran at all, which is the
                 # quieter failure and the one that survives a refactor.
                 "FAILED")
# Note: "timed out" is deliberately NOT a marker. The success message reads
# "none timed out" and a substring match on it fails every passing run --
# which is exactly what happened when it was added. The positive assertion
# below already requires the "none timed out" wording.


# Runs QEMU until `marker` appears in the log, or the timeout expires.
#
# The kernel halts rather than exiting, so waiting for QEMU to finish means
# waiting the entire timeout on *every* run, pass or fail. That coupling is
# what made the timeout impossible to tune: long enough to survive a loaded
# build machine also meant minutes of dead waiting per case. Polling separates
# the two -- a healthy boot finishes in seconds and the timeout goes back to
# being an upper bound rather than the running cost.
#
# **How long it took is recorded in `BOOT_ELAPSED_MS`, on every run.** Until
# 2026-08-25 the only run whose duration anyone learned was one that had
# already blown the budget, and a timeout that fires tells you nothing about
# how close the runs that passed were. That is the wrong way round: a boot
# creeping from a third of its budget to nine tenths is the thing worth seeing,
# and it is invisible right up to the moment it stops being a warning and
# becomes a red lane on somebody else's machine.
run_until() {
    local logfile="$1" marker="$2" limit="$3"; shift 3
    : > "$logfile"
    local started; started=$(date +%s%3N)
    BOOT_ELAPSED_MS=0
    timeout "$limit" qemu-system-x86_64 "$@" >/dev/null 2>&1 &
    local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if grep -qF -- "$marker" "$logfile" 2>/dev/null; then
            # Stamped *before* the settle sleep below, so the figure is time to
            # the marker and not time to the marker plus a constant this
            # harness chose.
            BOOT_ELAPSED_MS=$(( $(date +%s%3N) - started ))
            # Let the last few lines land before stopping the machine.
            sleep 1
            break
        fi
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((limit * 4)) ]] && break
    done
    [[ $BOOT_ELAPSED_MS -eq 0 ]] && BOOT_ELAPSED_MS=$(( $(date +%s%3N) - started ))
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 0
}

fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }

[[ -f "$ISO" ]] || { fail "$ISO not found -- run 'make iso' first"; exit 1; }

# The ramdisk image is attached as a disk as well as loaded as a module, so
# the block driver's test knows what must come back.
DISK="$REPO_ROOT/build/initrd.tar"
# A second disk, for the block driver that runs in a domain. Its own device:
# two drivers on one device would race resets and interleave rings, so the
# domain driver gets a device rather than a share of the kernel's.
DOMAIN_DISK="$REPO_ROOT/build/domain-disk.img"

# RFC 0012's escape hatch, and it is tested on a machine that **has** an IOMMU
# -- turning off a unit that is not there proves nothing. The image is built
# with the flag and the default is put back afterwards, the same way
# `shell-test.sh` handles `shell=kernel`.
#
# An escape hatch nobody exercises is not an escape hatch: it is a line of code
# that will be reached for the first time on the machine that is already going
# wrong. This one exists for M1-17's first boot on real hardware, which is
# exactly the situation where finding out it never worked would be worst.
if [[ "$MODE" == "iommu-off" ]]; then
    make -C "$REPO_ROOT" iso CMDLINE="iommu=off" >/dev/null 2>&1 || {
        fail "could not build an image with iommu=off"
        exit 1
    }
    restore_image() { make -C "$REPO_ROOT" iso >/dev/null 2>&1 || true; }
fi

# The machine, from `devices.sh`, which both QEMU harnesses share.
#
# It used to be built here and built again in `shell-test.sh`, and the two
# drifted: this file grew a network device and that one did not. See the header
# of `devices.sh` for what that cost.
#
# What stays here is the *policy* — which of this harness's modes want a unit —
# because that is genuinely this harness's business. `iommu-off` is in the list
# on purpose: the machine has a unit and the kernel is told to ignore it, which
# is the whole point of the escape hatch.
# shellcheck source=tests/qemu/devices.sh
source "$REPO_ROOT/tests/qemu/devices.sh"

if [[ "$MODE" == "iommu" || "$MODE" == "fsd" || "$MODE" == "iommu-off" ]]; then
    qemu_device_list full yes
else
    qemu_device_list full no
fi

QEMU_ARGS=(-M "$MACHINE" -cpu ${QEMU_CPU:-max} -smp "${QEMU_SMP:-4}" -m 256M -no-reboot
           -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on"
           -drive "file=$DOMAIN_DISK,format=raw,if=none,id=disk1"
           "${VIRTIO_ARGS[@]}"
           "${IOMMU_ARGS[@]}"
           -serial "file:$LOG" -display none)

# The boot media is the one thing the native mode changes: every other line
# of this harness -- the machine, the disks, the network, and all of the
# gates below -- runs identically over both loaders. That identity is RFC
# 0028 step 7's closing claim, made executable: `bhaskixboot.efi` is held to
# the same 126 gates the incumbent has answered since M1.
if [[ "$MODE" != "native" ]]; then
    QEMU_ARGS+=(-cdrom "$ISO" -boot d)
fi

if [[ "$MODE" == "uefi" || "$MODE" == "native" ]]; then
    # OVMF ships as a CODE/VARS *pair* and they must be searched as one.
    #
    # An earlier version looked for each independently, which broke on
    # distributions that ship only the 4 MB variant: CODE was found, VARS was
    # not, and QEMU was handed `-drive file=<nonexistent>`. It exited before
    # producing a byte of output, so the failure looked like a kernel that
    # would not boot.
    #
    # The two images must also be the same size -- a 4 MB CODE with a 2 MB VARS
    # is rejected by the firmware, not by QEMU, which is a worse place to find
    # out. Hence pairs, in preference order, newest layout first.
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
        # Distinguish "not installed" from "installed but unusable". The first
        # is a fine reason to skip; the second is a broken environment and
        # skipping would hide it.
        if compgen -G "/usr/share/OVMF/*.fd" >/dev/null 2>&1 \
           || compgen -G "/usr/share/edk2/ovmf/*.fd" >/dev/null 2>&1; then
            fail "OVMF is installed but no complete CODE/VARS pair was found"
            echo "        images present:" >&2
            ls -1 /usr/share/OVMF/*.fd /usr/share/edk2/ovmf/*.fd 2>/dev/null | sed 's/^/          /' >&2
            exit 1
        fi
        printf '\033[1;33mskip\033[0m  uefi boot test (OVMF not installed)\n'
        exit 0
    fi

    echo "using firmware: $(basename "$OVMF_CODE") + $(basename "$OVMF_VARS")"

    # VARS is writable, so it must be a private copy rather than the packaged
    # image -- the firmware writes its variable store on every boot.
    mkdir -p "$REPO_ROOT/build"
    WRITABLE_VARS="$REPO_ROOT/build/OVMF_VARS_${MODE}.fd"
    cp "$OVMF_VARS" "$WRITABLE_VARS"

    QEMU_ARGS+=(-drive "if=pflash,unit=0,format=raw,readonly=on,file=$OVMF_CODE"
                -drive "if=pflash,unit=1,format=raw,file=$WRITABLE_VARS")
fi

if [[ "$MODE" == "native" ]]; then
    # The native loader boots from an ESP directory, staged fresh: its own
    # binary at the removable-media path, the payload at the fixed paths the
    # loader reads. A directory of its own, so the loader-specific lane's
    # negative arm (which corrupts its staged kernel in place) can never
    # bleed into this one.
    LOADER="$REPO_ROOT/boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi"
    KERNEL_ELF="$REPO_ROOT/target/x86_64-unknown-none/release/bhaskix"
    if [[ ! -f "$LOADER" || ! -f "$KERNEL_ELF" ]]; then
        fail "the native loader or the kernel is not built -- run 'make test-boot-native' deps first"
        exit 1
    fi
    ESP="$REPO_ROOT/build/native-full-esp"
    rm -rf "$ESP"
    mkdir -p "$ESP/EFI/BOOT" "$ESP/bhaskix"
    cp "$LOADER" "$ESP/EFI/BOOT/BOOTX64.EFI"
    cp "$KERNEL_ELF" "$ESP/bhaskix/kernel"
    cp "$DISK" "$ESP/bhaskix/initrd.tar"
    printf 'cmdline=\n' > "$ESP/bhaskix/boot.conf"
    # **Explicitly on a port of its own, and this is not tidiness.**
    #
    # A bare `-drive` takes `if=ide` and QEMU auto-assigns it the first free
    # index -- which is `ide.0`, where RFC 0046's SATA disk now sits. q35's
    # `ich9-ahci` gives each port a bus of one unit, so the two collided and
    # **QEMU exited before producing a byte**: `Can't create IDE unit 1, bus
    # supports only 1 units`. The lane then failed as "the machine did not
    # finish booting" with an empty serial log, which reads as a loader that
    # hangs rather than as a machine that never started -- and it stayed that
    # way from 2026-08-24, when the SATA disk landed, because `make gates`
    # does not run the boot lanes and `make test` was red for other reasons.
    #
    # `index=2` because that is where the boot medium sits on every other lane:
    # `-cdrom` lands there once the SATA disk holds `ide.0`, which is how RFC
    # 0046 step 4 came to find the boot CD answering `IDENTIFY` with ATAPI's
    # abort. One index for "the thing this machine was booted from", whichever
    # lane is booting it.
    #
    # Said with `if=ide,index=` and not with a `-device`, because this is boot
    # *media* and not machine hardware -- the same reason `-cdrom` above is a
    # flag here rather than a device in `devices.sh`. `tools/check-one-machine.sh`
    # enforces exactly that line and refused the first version of this fix,
    # which is the gate doing its job on the person adding a gate.
    QEMU_ARGS+=(-drive "if=ide,index=2,format=raw,file=fat:rw:$ESP")
fi

# The domain's disk is written to now, so it is rebuilt before every run.
# A fixture a test mutates is a fixture whose next run starts somewhere nobody
# chose, and this one carries the marker other checks look for in sector zero.
rm -f "$REPO_ROOT/build/domain-disk.img"
make -C "$REPO_ROOT" build/domain-disk.img >/dev/null 2>&1 || true

# And the SATA disk, for the same reason and since RFC 0046 step 6: the AHCI
# driver now *writes* to it -- a pattern into its last sector, read back to
# prove the write happened. Sector zero carries the marker the read gate checks,
# and leaving a mutated fixture in place would mean the next run starts wherever
# the last one left it.
rm -f "$REPO_ROOT/build/sata-disk.img"
make -C "$REPO_ROOT" build/sata-disk.img >/dev/null 2>&1 || true

# RFC 0020 step 5's inbound driver: a host-side client that connects *into*
# the guest through hostfwd, sends sixteen bytes, and demands them back.
# The guest's listener arms only after its outbound demonstration completes,
# so this reattempts for the whole boot; each attempt is cheap and the loop
# dies with the boot. `/dev/tcp` is bash itself, so the harness needs no new
# tool. The verdict lands in a file, because the driver is a background job
# and its exit status would be lost. On a machine with no network the
# connection is never accepted, the file stays absent, and the gate's dark
# arm expects exactly that.
#
# **What makes "reattempts" true is that the guest refuses** (RFC 0047), and
# it is worth knowing why, because this loop retries only when `connect`
# fails and slirp's `hostfwd` accepts on the host side whatever the guest
# does. Before `bin/tcpd` answered a shut port with a `RST`, the first
# connection blocked in the read below for the entire boot -- measured, 20
# boots out of 20 -- and the whole gate rode slirp's SYN-retransmit ladder,
# which puts a rung at roughly T+6 s and the next at T+18 s. That left about
# a tenth of a second of margin against the guest's listener, and it is the
# mechanism behind the intermittent TRACKER filed on 2026-08-24.
#
# **And the limit of that, stated rather than left to be discovered.** A
# `RST` can only come from a guest that is *reachable*; a connection whose
# SYN lands before the guest has an address gets no answer from anybody and
# still waits for the next rung. Refusing a shut port removes the razor
# edge, it does not remove the ladder.
INBOUND_VERDICT=$(mktemp)
rm -f "$INBOUND_VERDICT"
(
    payload='bhaskix-tcp-in-1'
    for _ in $(seq 1 "$TIMEOUT"); do
        if { exec 3<>/dev/tcp/127.0.0.1/45557; } 2>/dev/null; then
            printf '%s' "$payload" >&3
            reply=$(dd bs=1 count=16 <&3 2>/dev/null || true)
            exec 3>&- 3<&- || true
            if [[ "$reply" == "$payload" ]]; then
                echo "echoed" > "$INBOUND_VERDICT"
                exit 0
            fi
        fi
        sleep 1
    done
) &
INBOUND_DRIVER=$!

# RFC 0047's gate: a connection to a port nobody holds must be *refused*, and
# refused promptly.
#
# Until RFC 0047 `bin/tcpd` could not refuse one at all -- a `SYN` naming no
# connection and no listener was dropped, silently, because the only path to
# the wire needed a control block. The peer therefore heard nothing and
# retransmitted for its whole connect timeout. That is what made the inbound
# gate above a coin flip: the driver's retry loop only retries when *connect*
# fails, and slirp's `hostfwd` always accepts, so the one connection it opened
# rode slirp's SYN backoff into or past the guest's ten-second accept window.
#
# The probe waits for `$INBOUND_VERDICT` first, deliberately. That file is
# proof the guest is networked *and* serving, so a refusal seen after it is
# the machine refusing rather than the machine being absent -- which is the
# difference this gate would otherwise be unable to state. Its own verdict is
# three-valued for the same reason: refused, never-refused, and never-asked.
#
# `timeout` is what makes it a test. A `RST` closes the connection at once and
# `dd` reads end-of-file with nothing in it; with no `RST` the read blocks
# past the end of the boot. Sixteen bytes are asked for and zero are required:
# a port nobody holds has nothing to say.
CLOSED_VERDICT=$(mktemp)
rm -f "$CLOSED_VERDICT"
(
    until [[ -f "$INBOUND_VERDICT" ]]; do
        sleep 0.25
    done
    for _ in $(seq 1 "$TIMEOUT"); do
        if { exec 4<>/dev/tcp/127.0.0.1/45558; } 2>/dev/null; then
            if stray=$(timeout 3 dd bs=1 count=16 <&4 2>/dev/null); then
                exec 4>&- 4<&- || true
                if [[ -z "$stray" ]]; then
                    echo "refused" > "$CLOSED_VERDICT"
                else
                    echo "answered: $stray" > "$CLOSED_VERDICT"
                fi
                exit 0
            fi
            exec 4>&- 4<&- || true
        fi
        sleep 1
    done
) &
CLOSED_DRIVER=$!

echo "booting ($MODE), up to ${TIMEOUT}s..."
run_until "$LOG" "Nothing left to do at this milestone" "$TIMEOUT" "${QEMU_ARGS[@]}"
kill "$INBOUND_DRIVER" 2>/dev/null || true
wait "$INBOUND_DRIVER" 2>/dev/null || true
kill "$CLOSED_DRIVER" 2>/dev/null || true
wait "$CLOSED_DRIVER" 2>/dev/null || true

status=0

# If the machine never finished booting, every assertion below fails for one
# reason and prints thirty of them. That wall of red says nothing about which
# thing broke, and it has twice been mistaken for a catastrophic regression
# when the actual cause was a second QEMU holding the disk image or a loaded
# host. One accurate line is worth more than thirty misleading ones.
if ! grep -qF "Nothing left to do at this milestone" "$LOG"; then
    fail "the machine did not finish booting within ${TIMEOUT}s (gave up after $((BOOT_ELAPSED_MS / 1000)).$(printf '%03d' $((BOOT_ELAPSED_MS % 1000)))s)"
    if [[ ! -s "$LOG" ]]; then
        echo "        the serial log is empty -- qemu may not have started at all" >&2
        echo "        (a second run holding build/initrd.tar is the usual cause)" >&2
    else
        echo "        it got as far as:" >&2
        tail -5 "$LOG" | sed 's/^/          /' >&2
    fi
    echo "--- serial log ---" >&2
    cat "$LOG" >&2
    exit 1
fi

# **What fraction of its own budget this boot used.** Reported, never asserted:
# a wall-clock threshold here would be a test of whichever machine is running
# it, which is the objection this file makes to performance budgets elsewhere
# and means here too. What it buys is that the margin becomes visible on runs
# that *pass* -- so a lane drifting toward its limit is a number somebody can
# watch, instead of a red boot on a machine nobody can reproduce.
#
# It is the answer this harness could not give when two CI boot lanes went red
# on 2026-08-25 and seven local runs would not reproduce either: local boots
# here take 32-39s of a 120s budget, and whether CI's take 40 or 115 was
# unknown and unknowable, because nothing measured a passing run.
elapsed_s="$((BOOT_ELAPSED_MS / 1000)).$(printf '%03d' $((BOOT_ELAPSED_MS % 1000)))"
used_pct=$(( BOOT_ELAPSED_MS / (TIMEOUT * 10) ))
if [[ $used_pct -ge 50 ]]; then
    printf '\033[1;33mnote\033[0m  booted in %ss, which is %s%% of the %ss budget -- close enough to the limit to be worth saying\n' \
        "$elapsed_s" "$used_pct" "$TIMEOUT"
else
    printf '\033[2mnote\033[0m  booted in %ss, %s%% of the %ss budget\n' \
        "$elapsed_s" "$used_pct" "$TIMEOUT"
fi
# **And said again where it can be read without a token.**
#
# The measurement above was added so the margin would be visible on runs that
# *pass* -- and on CI it was visible to nobody, because a job's log needs
# authentication to fetch and the boot log is uploaded only `if: failure()`.
# The instrument answered the question everywhere except the one place the
# question was asked. A workflow `::notice::` becomes an annotation on the run,
# which is the one channel here that survives both.
[[ -n ${GITHUB_ACTIONS:-} ]] && \
    echo "::notice title=Boot budget ($MODE)::booted in ${elapsed_s}s, ${used_pct}% of the ${TIMEOUT}s budget"

if grep -qF "$EXPECT_GREETING" "$LOG"; then
    pass "greeting present"
else
    fail "greeting '$EXPECT_GREETING' not found on serial"
    status=1
fi

for marker in "${FAILURE_MARKERS[@]}"; do
    if grep -qF "$marker" "$LOG"; then
        fail "found failure marker: $marker"
        status=1
    fi
done

# Reaching the last line proves the kernel ran to completion rather than
# faulting somewhere in the middle -- which a greeting alone would not show.
#
# Deliberately milestone-agnostic: an earlier version matched "M1 complete" and
# broke the moment the banner said M3, which is a test failing on its own
# wording rather than on the kernel.
if grep -qF "Nothing left to do at this milestone" "$LOG"; then
    pass "kernel_main ran to completion"
else
    fail "the kernel did not run to completion"
    status=1
fi

# M2: interrupts must actually be delivered, not merely enabled. Asserting on
# observed ticks rather than on "interrupts ENABLED" is the difference between
# testing that the code ran and testing that the hardware responded.
if grep -qF "timer          delivering" "$LOG"; then
    pass "timer interrupts delivered"
else
    fail "no timer interrupts were delivered"
    status=1
fi

if grep -qF "hlt wakes on interrupt" "$LOG"; then
    pass "hlt wakes on interrupt (idle path)"
else
    fail "hlt did not wake on a timer interrupt"
    status=1
fi

# M3: the physical allocator and the heap, asserted on real memory rather than
# only in host unit tests.
if grep -qF "self test      passed, no frames leaked" "$LOG"; then
    pass "buddy allocator: no frames leaked"
else
    fail "physical allocator self test did not pass"
    status=1
fi

if grep -qF "heap           alloc works, no frames leaked" "$LOG"; then
    pass "kernel heap: Box and Vec work, no frames leaked"
else
    fail "kernel heap self test did not pass"
    status=1
fi

if grep -qF "no-execute     enabled" "$LOG"; then
    pass "no-execute enabled (W^X enforceable)"
else
    fail "no-execute is not enabled -- W^X cannot be enforced"
    status=1
fi

# The M3 exit gate from docs/memory.md §7. Negative-tested: removing the
# page-table teardown leaks 9 frames per cycle and this catches it.
if grep -qF "created and destroyed, no frames leaked" "$LOG"; then
    pass "1000 address spaces created and destroyed, no frames leaked"
else
    fail "address space frame-leak gate did not pass"
    status=1
fi

if grep -qF "guard page     unmapped and below the stack" "$LOG"; then
    pass "kernel runs on a guarded stack"
else
    fail "the kernel is not on a guarded stack"
    status=1
fi

# The design's central claim: the region map decides, the page table follows.
# Negative-tested -- breaking the demand-paging arm produces an unhandled page
# fault rather than a silent pass.
if grep -qF "faults serviced from the region map" "$LOG"; then
    pass "demand paging and copy-on-write work in a live address space"
else
    fail "demand paging / copy-on-write did not pass"
    status=1
fi

# The other half of the same mechanism, and the half that has actually gone
# wrong. A write performed by the CPU faults on a lazily mapped page and the
# handler services it; a write performed by the kernel through the direct map,
# into a space it is not running in, takes no fault at all and must commit the
# page itself. Three bugs of one shape landed on 2026-08-20 because that rule
# lived in a comment -- `wait4`'s status word, `pipe2`'s descriptor pair and
# every `read` into a fresh buffer, each answering EFAULT for memory the
# program had legitimately mapped.
#
# Both directions are asserted by the self-test behind this line, and both were
# watched failing: a write that does not commit (the original bug, put back),
# and -- the direction people forget -- a read that does.
if grep -qF "a write commits, a read does not" "$LOG"; then
    pass "a supervisor's write commits a lazily mapped page, and its read does not"
else
    fail "the supervisor-write invariant did not hold"
    status=1
fi

# SMEP and SMAP turn whole classes of exploitation primitive into faults, and
# uaccess depends on the exception table existing at all.
# A single boot cannot prove the base is *random*, only that a slide was
# applied at all -- which is the part that can silently regress. Losing KASLR
# looks identical to having it unless the number is checked.
# Threads exist and the timer preempts them. The workers never yield, so a
# counter that advanced can only have been put on the CPU by the timer --
# negative-tested by removing the preempt call, which zeroes every count.
# Every reported CPU must come online. Asserting "N of N" rather than
# "more than one" catches a CPU that silently never arrives, which otherwise
# reads as success on a machine that happens to be smaller.
if grep -qE "cpus +([0-9]+) online of \1 reported" "$LOG"; then
    pass "all reported CPUs came online"
else
    fail "not every reported CPU came online"
    status=1
fi

# Shootdown reaching nobody looks exactly like shootdown working, so a count is
# what gets checked. Negative-tested by disabling the receiving handler, which
# turns 8 completions into 8 timeouts.
#
# **This comment used to say the acknowledgement count is what gets checked, and
# it is not** — `acknowledged` never reaches the line. What is printed is
# `new_completions`, a different counter, and the pattern accepted zero for it
# until 2026-08-11. The acknowledgement *is* checked, in `smp.rs`, which refuses
# to print this line unless all eight arrived; so the property was gated, just
# not by the gate that claimed to. Both halves are now true: the kernel checks
# the acknowledgements, and this requires the completions it prints to be
# non-zero.
if grep -qE "tlb shootdown +[1-9][0-9]* completed across [1-9][0-9]* cpus, none timed out" "$LOG"; then
    pass "TLB shootdown acknowledged by every CPU"
else
    fail "TLB shootdown did not complete on every CPU"
    status=1
fi

# Two properties in one line, and both matter. The preemption count says the
# timer drove a switch at all; "each worker ran on its own cpu" says the
# runqueues are genuinely per-CPU. A single global queue would still preempt --
# it would just run every worker wherever a slot came free, which is exactly
# what this milestone claims to have stopped doing.
if grep -qE "threads +[0-9]+ preemptions across [0-9]+ cpus; each worker ran on the cpu it was created on" "$LOG"; then
    pass "threads preempted by the timer, each on its own runqueue"
else
    fail "per-CPU timer-driven preemption did not work"
    status=1
fi

# The five below were added on 2026-08-11, after an audit found their self-tests
# had no gate at all. Each ran on every boot and reported into a log nothing
# read, so any of them could have started failing and the suite would have
# stayed green.
#
# They assert *shape*, not values: the numbers move with host load — this suite
# has run under a fuzzing campaign all day — and a gate that pinned them would
# fail for the machine being busy, which is the fastest way to get a gate
# ignored. What each one asserts is that the test ran and reported the thing it
# exists to report.

# Killing a thread that is queued to send must leave nothing behind. A stale
# entry would have a later rendezvous deliver to a thread that is gone.
if grep -qE "queue cleanup +a thread killed while queued to send left no entry behind" "$LOG"; then
    pass "a killed sender leaves no queue entry behind"
else
    fail "the queued-sender cleanup was not reported"
    status=1
fi

# The counters behind it. `naming a thread that has gone` is the one that
# matters and must be zero; the rest move with what the boot did.
if grep -qE "endpoint queues [0-9]+ senders and [0-9]+ receivers queued, 0 naming a thread that has gone" "$LOG"; then
    pass "no endpoint queue entry names a thread that has gone"
else
    fail "endpoint queues were not reported, or one named a departed thread"
    status=1
fi

# Two scheduling classes, and that over-commit is refused. The measured ratio is
# deliberately not pinned: `scheduler.md` §4 records that a 3:1 weight delivered
# 3.7:1 on hardware, so a gate on the number would be a gate on the host.
if grep -qE "sched classes +weight 3:1 measured [0-9.]+x; rt took [0-9]+ ticks against fair's [0-9]+; over-commit refused" "$LOG"; then
    pass "the scheduling classes are measured and over-commit is refused"
else
    fail "the scheduling-class measurement was not reported"
    status=1
fi

# RFC 0026 step 2: the telemetry plane's boot report. The values are not
# asserted beyond sanity -- a slow host is not a broken kernel -- but the line
# must exist (an instrument that measured nothing is a failure even where slow
# is not), events must be nonzero (the scheduler emits on every switch, and a
# boot performs thousands), and audit-refused must be zero, because nothing may
# emit the reserved class until the audit RFC builds its backpressure ring.
if grep -qE "telemetry +[1-9][0-9]* events across [1-9][0-9]* cpus, [0-9]+ dropped, 0 audit-refused; ~[0-9]+ cycles/emit over [0-9]+, ~[0-9]+ disabled; [1-9][0-9]* slots/cpu" "$LOG"; then
    pass "telemetry: events counted, drops said, the reserved class untouched"
else
    fail "the telemetry report line is missing or malformed"
    status=1
fi

# RFC 0026 steps 3-4: the round trip. Marked probe events emitted on every CPU
# must all come back through bin/traced -- a ring 3 program holding the rings
# read-only and the tails read-write, and nothing else. The kernel compares
# the counts and prints "all N ... read back" only on exact agreement, with
# zero refused decodes and zero mis-attributed CPUs behind it.
if grep -qE "traced +all [1-9][0-9]* probe events read back through granted rings; [1-9][0-9]* events decoded, 0 refused; [1-9][0-9]* sched \+ [1-9][0-9]* syscall events, [1-9][0-9]* passes" "$LOG"; then
    pass "telemetry round trip: the marked set came back through capabilities"
else
    fail "bin/traced did not read back the marked set"
    status=1
fi

# Wakeup latency. **The target is not asserted** and that is deliberate: §10's
# figure is unmet under an interpreting emulator and TRACKER says so. What is
# asserted is that the measurement happened, so the day it is taken on hardware
# there is a number to compare against rather than a silence.
if grep -qE "rt latency +[1-9][0-9]* wakeups, worst [0-9.]+ (us|ticks)" "$LOG"; then
    pass "wakeup latency is measured and reported"
else
    fail "no wakeup-latency measurement was reported"
    status=1
fi

# RFC 0041 rule 1, watched rather than asserted: a real xHCI controller is in
# this machine (devices.sh, `full` profile), it is behind no IOMMU translation,
# and the kernel must refuse it by name. A bus master with unmediated access to
# memory is the thing this rule exists to stop, and a refusal that never fires
# in a test is a refusal nobody has seen work.
if grep -qaE 'xhci +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]+ [0-9a-f]{4}:[0-9a-f]{4} REFUSED' "$LOG"; then
    pass "an xHCI controller without IOMMU translation is found and refused"
else
    fail "the xHCI controller was not found, or was not refused"
    grep -a "xhci" "$LOG" | sed 's/^/      /'
    status=1
fi

# RFC 0041 step 3, on the lanes that have a unit. The machine has *two*
# controllers and the kernel builds a window for the first only, so both halves
# of the rule have a live subject on one boot: the gate above watches the second
# be refused, and this one watches the first be driven.
#
# Guarded by mode for the same reason every other unit-dependent gate here is:
# on a lane with no IOMMU **both** controllers are correctly refused, and rule 1
# says that is the right answer rather than a failure. Asserting a bring-up
# there would be asserting that the rule is broken.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    # **The fault instrument ran, at both moments it is asked to.**
    #
    # This is the third time this project has found the same shape, so the gate
    # is for the shape and not for this instance. `iommu::faulted` was written
    # for RFC 0012 and had **no callers** for months. `take_fault` read record
    # zero only and printed nothing when it found none, so "no fault in slot
    # zero" was indistinguishable from "this did not run". Between them they
    # cost a four-boot hunt on a live server, and RFC 0049 came out of it.
    #
    # What replaced them is `report_faults_since`, printed twice on every boot
    # with a unit -- and, until 2026-08-25, matched by **no gate at all**. An
    # instrument nobody asserts is an instrument that can stop running quietly,
    # which is the exact failure it was built to end.
    #
    # **What is asserted is that it spoke, not what it said.** A fault is not a
    # failure: the first genuine DMA refusal this project ever recorded from
    # real hardware was containment working, and a gate demanding "none
    # recorded" would go red on the machine behaving correctly. So either form
    # counts -- the summary line when there were none, or a fault line when
    # there were -- and both moments must produce one.
    for moment in "before drivers" "during bring-up"; do
        if grep -qaE "iommu faults? +\[$moment\]" "$LOG"; then
            pass "the IOMMU fault records are read and reported [$moment]"
        else
            fail "nothing reported IOMMU faults [$moment] -- the instrument did not run"
            grep -a "iommu" "$LOG" | sed 's/^/      /'
            status=1
        fi
    done

    # The counts are required to be non-zero rather than exact. Slots and ports
    # are the controller's own numbers and an emulator is entitled to change
    # them between versions -- but zero of either means the capability bank was
    # not read, which is the failure this is for.
    if grep -qaE 'xhci +running, [1-9][0-9]* slots, [1-9][0-9]* ports' "$LOG"; then
        pass "the translated xHCI controller is brought up and reports its slots and ports"
    else
        fail "the xHCI controller behind a window was not brought up"
        grep -a "xhci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # And it got a window of its own. Named separately from the bring-up
    # because they fail apart: the bring-up could be made to work by dropping
    # rule 1, and this is what says the containment is real.
    if grep -qa "the xhci controller's own page table and domain" "$LOG"; then
        pass "the xHCI controller translates through a page table and domain of its own"
    else
        fail "no separate IOMMU window for the xHCI controller"
        grep -a "iommu window" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0041 step 4: both rings, in both directions, and a gate a coincidence
    # cannot pass.
    #
    # A running controller is only a controller that is not halted. This asserts
    # a *conversation*: a No-Op command written to the command ring, the
    # doorbell rung, and a Command Completion Event that names the address the
    # command was written to. The address is what carries it -- an event that
    # merely arrived would prove the event ring works and say nothing about
    # whether the controller ever read the ring this driver writes.
    #
    # `success` and `dequeue advanced` are in the same pattern deliberately.
    # Without the dequeue write the interrupter is never re-armed, which is a
    # ring that works exactly once and would pass a weaker gate every time.
    if grep -qaE 'xhci rings +answered the no-op at 0x[0-9a-f]+: [1-9][0-9]* event.*success, dequeue advanced' "$LOG"; then
        pass "the xHCI command and event rings carry a no-op round trip, matched by address"
    else
        fail "the xHCI rings did not carry a matched no-op round trip"
        grep -a "xhci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0041 step 5: a real device, a slot, and an address.
    #
    # `devices.sh` puts a USB keyboard on the controller this kernel drives, so
    # there is something to enumerate. The gate asserts the whole chain -- a
    # port with a device on it, a slot the controller handed out, and a USB
    # address -- because each link fails differently and a driver that found a
    # port and stopped would otherwise look the same as one that finished.
    #
    # **`slot state addressed` is the part that is read back from the
    # controller's own memory.** Address Device answering Success says the
    # command was accepted; the device context saying `Addressed` says the
    # controller did what the command asked. The two came apart on 2026-08-23:
    # the command was refused outright with TrbError because the root hub port
    # number was being written into the Number of Ports field.
    #
    # Ports and slots are not pinned to particular numbers. Which port QEMU
    # puts a keyboard on is its business and has changed between versions; that
    # a device was found, given a slot and addressed is this kernel's.
    if grep -qaE 'xhci device +port [1-9][0-9]* at speed [1-9][0-9]*.*slot [1-9][0-9]*, addressed [1-9][0-9]* \(slot state addressed\)' "$LOG"; then
        pass "a USB device is found on a port, given a slot, and addressed"
    else
        fail "no USB device was enumerated and addressed"
        grep -a "xhci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0041 step 6, first half: the device is asked what it is, and answers.
    #
    # This is the first control transfer -- setup, data and status stages on the
    # control endpoint's own ring -- so it asserts the whole path rather than
    # any one register. `context index 3` is the part that carries the most:
    # the Device Context Index is not the endpoint number, and a driver that
    # conflates them polls a mouse for keystrokes. Endpoint 1 IN is index 3.
    #
    # The vendor and product are not pinned. Which keyboard QEMU emulates is its
    # business; that the descriptor parsed into a boot keyboard is this
    # kernel's.
    if grep -qaE 'xhci descrip +[0-9a-f]{4}:[0-9a-f]{4} said 18 bytes of device.*a boot keyboard on endpoint [1-9][0-9]* in, context index 3' "$LOG"; then
        pass "a USB device answers a control transfer and is parsed as a boot keyboard"
    else
        fail "no descriptors were read over a control transfer"
        grep -a "xhci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0041 step 6, second half: the interrupt IN endpoint is configured.
    #
    # `running` is read back from the device context the controller wrote, not
    # inferred from the command's completion code -- the same distinction that
    # caught a real bug at step 5. An endpoint that is not Running will not
    # accept a doorbell, which is what step 7 needs.
    if grep -qa "xhci endpoint  configured, running" "$LOG"; then
        pass "the keyboard's interrupt IN endpoint is configured and running"
    else
        fail "the interrupt IN endpoint was not configured"
        grep -a "xhci" "$LOG" | sed 's/^/      /'
        status=1
    fi
fi

# RFC 0046 step 2. `q35` has a SATA AHCI controller at `00:1f.2` on every lane
# in this file -- it is part of the machine, not something devices.sh adds -- so
# the same controller is a live subject for both halves of the rule and which
# half fires is decided by the lane rather than by a second device.
#
# Untranslated, which is every lane without a unit: refused by name. This is
# RFC 0012's rule on the endpoint RFC 0043 named as one of three with no driver,
# therefore no window, therefore no containment.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    # Behind a window of its own, on the lanes that have a unit. Two assertions
    # because they fail apart: the first is the driver's own account of what it
    # found, the second is the kernel's account of what it built, and a report
    # that claimed "translated" with no window behind it is exactly the failure
    # worth catching.
    if grep -qaE 'ahci +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]+ [0-9a-f]{4}:[0-9a-f]{4}, translated' "$LOG"; then
        pass "the SATA AHCI controller is found and translated"
    else
        fail "the AHCI controller was not found, or is not translated"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    if grep -qa "the ahci controller's own page table and domain" "$LOG"; then
        pass "the AHCI controller translates through a page table and domain of its own"
    else
        fail "no separate IOMMU window for the AHCI controller"
        grep -a "iommu window" "$LOG" | sed 's/^/      /'
        status=1
    fi
else
    if grep -qaE 'ahci +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]+ [0-9a-f]{4}:[0-9a-f]{4} REFUSED: no iommu' "$LOG"; then
        pass "an AHCI controller without IOMMU translation is found and refused"
    else
        fail "the AHCI controller was not found, or was not refused"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi
fi

# RFC 0046 step 3b: the controller is not merely found, it runs -- and a driver
# in ring 3 is what ran it. The counts are required to be plausible rather than
# exact: ports and slots are the controller's own numbers and an emulator is
# entitled to change them between versions, but zero ports or zero slots means
# the capability register was not read, which is the failure this is for.
#
# **This gate is also what checks RFC 0046's recalled register offsets.** There
# is no AHCI specification on the machine this was written on, so the constants
# came from memory; a wrong `PI` offset shows here as an implausible port count
# and a wrong `GHC` offset as a reset that never settles.
#
# IOMMU lanes only, and for the reason RFC 0041's bring-up gate gives: on a lane
# with no unit the controller is correctly refused a window, and asserting a
# bring-up there would be asserting the rule is broken.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    if grep -qaE 'ahci +up: [1-9][0-9]* ports? implemented \(0x[0-9a-f]+\), [1-9][0-9]* slots?' "$LOG"; then
        pass "the AHCI controller is brought up from ring 3 and reports its ports and slots"
    else
        fail "the AHCI controller was not brought up"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # And a port was actually interrogated. Named separately from the bring-up
    # because they fail apart: a controller can come up and report its
    # capabilities while every `PxSSTS` read lands on the wrong offset, and
    # `DET` is the register RFC 0046 exists to reach -- the one that answers
    # "is there a disk on this port", which the bus survey could not.
    if grep -qaE 'ahci port [0-9]+ +det [0-9]+ ipm [0-9]+' "$LOG"; then
        pass "each implemented port's SATA status is read and reported"
    else
        fail "no port status was reported"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0046 step 4: the first command this system has ever issued to a SATA
    # device, and the first thing a disk has said about itself.
    #
    # The signature gate comes first because it is what makes the identify gate
    # meaningful. `q35` puts the boot CD on this same controller and an ATAPI
    # device **aborts IDENTIFY DEVICE by specification** -- so a driver that
    # issued it blind would read the specification out of an error code, which
    # is exactly what happened on the first boot of step 4. `devices.sh` puts a
    # real disk on port 0 and leaves the CD on port 2, so the machine has one of
    # each and the driver has to tell them apart.
    if grep -qaE 'ahci port [0-9]+ +started; signature 0x00000101 -- a SATA disk' "$LOG"; then
        pass "a started port's signature identifies a SATA disk rather than the boot CD"
    else
        fail "no port was started, or its device was not identified as a disk"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # And the disk answered. Non-zero sectors and a sector size of at least 512
    # rather than exact numbers: the geometry is the image's and may change, but
    # zero of either means the 512 bytes were never read or were read from the
    # wrong place.
    if grep -qaE 'ahci identify +the disk answered: [1-9][0-9]* sectors of [5-9][0-9]{2,} bytes' "$LOG"; then
        pass "IDENTIFY DEVICE is issued and the disk answers with its own geometry"
    else
        fail "IDENTIFY DEVICE was not answered"
        grep -a "ahci" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0046 step 5: sector zero, read through the AHCI driver, and the bytes
    # are the ones that disk holds.
    #
    # **The content and not the success.** RFC 0046's testing plan asks for this
    # in as many words -- "a driver that returned zeroes would pass anything
    # weaker" -- so the string is matched. `build/sata-disk.img` is written with
    # `BHASKIX-SATA-DISK-SECTOR-0` and the *domain* disk with
    # `BHASKIX-DOMAIN-DISK-SECTOR-0`, so a driver that read the wrong device
    # fails here rather than passing plausibly.
    if grep -qa 'ahci read      sector 0 begins "BHASKIX-SATA-DISK-SECTOR-0' "$LOG"; then
        pass "sector 0 is read through the AHCI driver and holds that disk's own bytes"
    else
        fail "sector 0 was not read, or did not hold what that disk holds"
        grep -a "ahci read\|ahci identify" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0046 step 6: a write, proved by reading it back.
    #
    # Byte-for-byte, and on a sector that is **not** sector zero -- that one
    # holds the bytes the read gate above checks, and a driver that verified its
    # writes by destroying another gate's subject would be trading one proof for
    # another. The pattern the driver writes is derived from the sector number,
    # so writing sector N and reading sector M cannot agree with itself and pass.
    if grep -qaE 'ahci write +sector [0-9]+ written and read back byte-for-byte' "$LOG"; then
        pass "a sector is written through the AHCI driver and reads back byte-for-byte"
    else
        fail "the write self-test did not confirm"
        grep -a "ahci write\|ahci read" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # RFC 0046 step 6b, and the RFC's actual claim: a filesystem that had to know
    # which driver was underneath would be a filesystem with a driver inside it.
    #
    # So this asks `bin/ahcid` through `block::READ` -- the same method
    # `bin/blkd` answers, called the same way -- and demands the SATA disk's own
    # sector-zero bytes back. The string is matched rather than the byte count,
    # for the same reason step 5's gate matches it: a service answering from the
    # wrong device, or answering zeroes, fails here instead of passing.
    #
    # And a sector past the end must be refused. That refusal happens in
    # `ahci::plan_read`, the same bound every other transfer this driver makes
    # goes through -- a disk refuses an out-of-range read too, so a service
    # without the check would look identical from outside.
    if grep -qaE 'ahci service +512 bytes of sector 0 through the block interface, and they are the SATA disk.s own; a sector past the end is refused' "$LOG"; then
        pass "the AHCI driver answers block::READ with that disk's own sector, and refuses one past the end"
    else
        fail "the AHCI block service did not answer, or answered wrongly"
        grep -a "ahci service\|ahci read" "$LOG" | sed 's/^/      /'
        status=1
    fi

    # The driver holds a window. Separate again: the bring-up above would work
    # just as well without one, and this is what says the controller it drives
    # is contained.
    if grep -qa "ahci domain    dma window granted" "$LOG"; then
        pass "the AHCI driver in ring 3 holds a DMA window for its controller"
    else
        fail "the AHCI driver was given no DMA window"
        grep -a "ahci domain" "$LOG" | sed 's/^/      /'
        status=1
    fi
fi

# The decline is reported. Deterministic, and it guards the gate below rather
# than duplicating it: that one bounds the *latency*, which only moves when a
# decline actually happens, and declines are rare. This one asserts the
# mechanism the fallback rests on -- hold a lock, ask for a preemption, and be
# told it was declined -- so a change that broke the reporting is caught on
# every boot instead of on the rare boot that would have needed it.
if grep -qa "a declined preemption reports itself" "$LOG"; then
    pass "a declined preemption reports itself, so a same-cpu spawn can fall back to the IPI"
else
    fail "preempt did not report a declined preemption -- a same-cpu spawn that declines is dropped again"
    status=1
fi

# Spawn-to-first-dispatch, bounded. Unlike the 50 us wakeup target above, this
# one IS asserted: with spawn requesting a reschedule it measures in the low
# thousands of microseconds, and without one it measured 446-500
# *milliseconds* -- a priority-90 thread waiting behind a spinning fair thread
# on a CPU whose timer had gone tickless because it was busy but alone.
#
# **This bound cannot separate the two distributions, and pretending otherwise
# cost a suite run** (2026-08-21). The failure it guards is a *uniform draw
# over the one-second idle backstop*, so it starts at zero; and a loaded host
# running several QEMU lanes at once pushes a perfectly healthy boot into the
# tens of milliseconds. The two overlap. Tightening 50 ms -> 20 ms on the
# reasoning that a 28,061 us sample "must have been" a backstop draw failed
# the very next full-suite run at **31,494 us with the fix in place** -- which
# is the evidence that the tens-of-ms tail is host weather, not the bug.
#
# So this is a loose sanity check and is documented as one. It catches about
# 95% of backstop draws, which is enough to notice, and it does not fire on
# host weather, which is what keeps it worth reading. **The real guard is the
# deterministic check above**: the hole needs a declined preemption to go
# unreported, and that is asserted on every boot without waiting for luck.
spawn_us=$(grep -aoE "spawn to first run [0-9]+ us" "$LOG" | grep -oE "[0-9]+" || echo "")
if [[ -n "$spawn_us" && "$spawn_us" -lt 50000 ]]; then
    pass "a spawned thread reaches its first dispatch promptly ($spawn_us us)"
else
    fail "spawn to first dispatch took ${spawn_us:-unmeasured} us -- the tickless spawn hole is back"
    # The measurement lives in the boot log, which is a temporary file this
    # script throws away -- so a failure used to arrive as a number with no
    # context, and the one thing worth knowing is on the same line: whether
    # any spawn had to fall back to the IPI. Printed here, kept here.
    grep -a "rt latency" "$LOG" | sed 's/^/      /'
    status=1
fi

# Tickless idle: an idle CPU must take far fewer ticks than a busy one. Asserted
# as a *comparison* rather than a threshold, because the absolute counts depend
# on how long the boot took.
if grep -qE "tickless +[0-9]+ ticks on [0-9]+ idle cpus, [0-9]+ on [0-9]+ of them busy" "$LOG"; then
    pass "tickless idle is measured on idle and busy CPUs"
else
    fail "the tickless measurement was not reported"
    status=1
fi

# A deadline is never honoured *early*, and the re-arm path actually runs.
#
# **Two structural assertions, and deliberately no threshold.** RFC 0019 step 4
# measured this system waking at the same instant whatever deadline was asked
# for -- `lateness ≈ C − d` with `C` about 325 ms -- because nothing brought a
# CPU's already-armed timer forward when a nearer deadline arrived.
# `arm_no_later_than` fixed it. These two gates are **not the same size**, and
# saying so is worth more than letting them look alike:
#
#   * **never early** is the *positive* half of a check the kernel already
#     makes. `deadline_self_test` prints `FAILED` on an early fire and on more
#     than 25 ms of lateness, and the `FAILED` marker above has been fatal
#     since 2026-08-11 -- so a return of the 325 ms defect was already caught.
#     What was not caught is that self-test **ceasing to run at all**, which is
#     precisely the distinction the marker's own comment draws. Until
#     2026-08-25 the word "deadline" appeared nowhere in this script.
#   * **the counter moved** is a new assertion. `time::hastened()` is printed
#     on every boot and, before today, read by **nothing** -- no kernel-side
#     refusal, no gate here. If nothing ever re-programs a CPU's timer that
#     figure is zero, which is the original defect's shape, and zero would have
#     gone by in silence. It reads 3 on `bios`, `uefi` and `iommu-off` and 4 on
#     `iommu`; the gate asks only for **non-zero**, because how many is a
#     property of a particular boot and not of the mechanism.
#
# What neither asserts is how late the wake was. A millisecond budget here
# would be a test of whichever machine CI runs on -- the same objection the
# round-trip gate below makes, and this file means it. The kernel owns the one
# loose bound there is, at 25 ms, and says in place why it is loose.
if grep -qF "never early" "$LOG"; then
    pass "a deadline is honoured and never fires early"
else
    fail "the deadline measurement is missing, or a wake came early"
    grep -aE "deadline" "$LOG" | sed 's/^/      /'
    status=1
fi

if grep -qE "deadline arms +[1-9][0-9]* brought this cpu's next interrupt forward" "$LOG"; then
    pass "a nearer deadline brings an armed timer forward"
else
    fail "no timer was ever brought forward -- the re-arm path did not run"
    grep -aE "deadline arms" "$LOG" | sed 's/^/      /'
    status=1
fi

# Sleeping. Three things have to be true at once, and each hides a different
# way of passing without working: laps prove no wakeup was lost (the ring stops
# dead if one is), sleeps prove the threads actually blocked rather than spun,
# and wakeups prove they were woken rather than merely preempted onto.
if grep -qE "wait queues +[0-9]+ laps around [0-9]+ cpus, slowest [1-9][0-9]*; [1-9][0-9]* sleeps, [1-9][0-9]* wakeups" "$LOG"; then
    pass "threads sleep and are woken, no lost wakeups"
else
    fail "wait queue / lost wakeup check did not pass"
    status=1
fi

# The initial ramdisk. First time the kernel parses something an attacker
# controls end to end -- the archive is a file on the boot medium. That a good
# archive parses is the modest half; that a bad one cannot make the parser
# misbehave is proved by a million mutated archives on the host.
if grep -qE "initrd +[0-9]+ KiB, [0-9]+ members, [0-9]+ directories; etc/hostname reads back" "$LOG"; then
    pass "initrd loaded and parsed as a ustar archive"
else
    fail "initrd was not loaded or did not parse"
    status=1
fi

# The VFS, and the ELF loader's parsing half. The entry address and the segment
# count are matched exactly rather than loosely: they come out of the file's own
# program headers, so a loader that stopped reading them -- or read them wrongly
# -- shows up here as a changed number rather than as a ring 3 failure with no
# obvious cause.
# The count is exact and is **the second place that has to change** when a
# program is added: the kernel's own self-test asserts it too. That is
# deliberate duplication -- the kernel checks that its VFS lists what is there,
# and this checks that the kernel said so out loud -- but it means adding a
# program fails twice, in two files, which is worth knowing before it happens
# rather than after. Seventeen since `bin/ahcid` joined, 2026-08-24.
if grep -qE "vfs +[0-9]+ entries in /, 17 in /bin; bin/probe is ELF64, entry 0x10000000, 3 segments" "$LOG"; then
    pass "paths resolve, bad paths are refused, and bin/probe parses as ELF64"
else
    fail "the VFS or the ELF parser did not pass"
    status=1
fi

# Device interrupts. The I/O APIC is the first piece of hardware Bhaskix
# programs that the firmware describes rather than the architecture fixes, so
# the numbers come out of the machine's own tables. The vector is matched
# exactly because it is a constant this kernel chose.
if grep -qE "io apic +at 0x[0-9a-f]+, [0-9]+ inputs, [0-9]+ overrides.*irq 4 -> gsi [0-9]+, vector 0x[0-9a-f]+" "$LOG"; then
    pass "I/O APIC found through ACPI and a device interrupt routed"
else
    fail "the I/O APIC was not found or the serial line was not routed"
    status=1
fi

# The vector allocator (RFC 0011 step 1). The vector is deliberately *not*
# matched against a constant above: it is allocated at claim time, and a test
# that pinned it would be asserting the thing the allocator exists to stop
# anyone depending on. What is asserted instead is that every vector in use has
# exactly one named owner -- because a collision is now a boot failure, and the
# table is how a person reading a log after one finds out what happened.
if grep -qE "vectors +[0-9]+ of 224 allocatable in use" "$LOG"; then
    missing=""
    for owner in "apic timer" "tlb shootdown ipi" "reschedule ipi" "serial" "apic error" "apic spurious"; do
        grep -qE "^ +0x[0-9a-f]{2}  $owner.?\$" "$LOG" || missing="$missing '$owner'"
    done
    if [[ -z "$missing" ]]; then
        pass "every interrupt vector in use has one named owner"
    else
        fail "the vector table is missing:$missing"
        status=1
    fi
else
    fail "no vector table was reported"
    status=1
fi

# The console can now read as well as write. The byte count must be non-zero:
# a self-test that reported zero bytes and passed would be asserting that
# nothing happened.
if grep -qE "shell +[0-9]+ commands; [1-9][0-9]* bytes read back through the interrupt path" "$LOG"; then
    pass "console input arrives by interrupt, and every shell command works"
else
    fail "console input or the shell did not pass"
    status=1
fi

# The services an unprivileged program is given. Checked here by calling the
# endpoints directly, so a protocol bug is reported as one rather than as a
# shell that prints nothing.
# Keyed on what the test observed and not on a counter: a service in its own
# domain has no way to add to a number the kernel prints, so a gate reading the
# counter would pass in one placement and fail in the other while the service
# behaved identically in both.
if grep -qE "services +[0-9]+ entries listed, [0-9]+ bytes read by message; a third caller was refused" "$LOG"; then
    pass "the console and filesystem services answer, and refuse a third caller"
else
    fail "the services did not pass"
    status=1
fi

# The first device Bhaskix finds rather than assumes: enumerated on the PCI
# bus, configured through its own capability list, driven by DMA. The sector
# count is the ramdisk image's, which is what makes "it read something" and
# "it read the right thing" different assertions.
if grep -qE "virtio-blk +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9] [1-9][0-9]* sectors .*status 0x0f" "$LOG"; then
    pass "virtio-blk found on the bus, read by DMA, refuses what it should"
else
    fail "the block device did not pass"
    status=1
fi

# `docs/memory.md` §5 commits the project to *printing* the degraded threat
# model when there is no IOMMU, rather than silently accepting one. A device
# that does DMA with no IOMMU can reach all of physical memory, and the moment
# that line stops appearing while a driver is still running is the moment the
# document became untrue.
#
# Either wording satisfies it, and that is the point: the line used to be a
# constant, so it passed on a machine with three IOMMUs by saying there were
# none. What is asserted is that the machine states its DMA threat model, not
# that it lacks the hardware.
if grep -qE "NO IOMMU: this device can reach all of physical memory|translating: this device reaches only what it was given" "$LOG"; then
    pass "the DMA threat model is reported rather than silently accepted"
else
    fail "a DMA-capable device was brought up without saying what can reach memory"
    status=1
fi

# The escape hatch, on a machine that has a unit to refuse. Three assertions,
# and the first is the one with teeth.
#
# **The DMAR must still be reported.** An escape hatch that also silences
# discovery takes away the one thing whoever is holding a misbehaving machine
# needs -- what the firmware actually declared. Turning the IOMMU off is not a
# reason to stop saying there is one.
#
# Then that the machine says plainly it is unprotected, and then that it
# reached the end of the boot: `iommu=off` is for a machine that cannot get
# past translation, so a hatch that boots no further than the thing it bypasses
# is worthless.
if [[ "$MODE" == "iommu-off" ]]; then
    if grep -qE "iommu +[1-9][0-9]* unit(s)? found, none programmed yet \(the dma line below is the verdict\); [0-9]+-bit addresses" "$LOG"; then
        pass "iommu=off still reports what the firmware declared"
    else
        fail "iommu=off silenced discovery -- the one thing a stuck machine needs"
        status=1
    fi
    if grep -qE "iommu +OFF by iommu=off:.*every device reaches all of memory" "$LOG"; then
        pass "the machine says it is unprotected, and what that costs"
    else
        fail "nothing said the IOMMU was off, or did not say what it means"
        status=1
    fi
    # Nothing may be translating. This catches a hatch that printed its line
    # and enabled the unit anyway -- which is the failure that would look fine
    # in the log and leave the machine exactly as stuck as before.
    if grep -qE "iommu (window|irq) +" "$LOG"; then
        fail "iommu=off printed its line and then programmed the unit anyway"
        status=1
    else
        pass "no window was built and no interrupt was remapped"
    fi
fi

# RFC 0012 step 1, and only on the machine that has one: the units the firmware
# describes are found and described. The qualifier is asserted with them --
# nothing is programmed at this step, and a line that claimed an IOMMU without
# saying so would read as protection the machine does not have.
#
# It said "not enabled" until 2026-08-24, which was a fixed string printed
# before bring-up and therefore identical on a machine where translation comes
# up and one where it does not. It cost a wrong reading of an SR550 boot. The
# verdict is `report_dma`'s line, and this one now says so.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    if grep -qE "iommu +[1-9][0-9]* unit(s)? found, none programmed yet \(the dma line below is the verdict\); [0-9]+-bit addresses" "$LOG"; then
        pass "the IOMMU the firmware describes is found and reported"
    else
        fail "an intel-iommu was present and the DMAR table was not read"
        status=1
    fi
    if grep -qE "iommu +WARNING" "$LOG"; then
        fail "the DMAR parsed only partially"
        status=1
    fi

    # RFC 0012 step 2: the structures are built, read back, and not programmed.
    #
    # "not programmed" is asserted with the rest. A window that had been shown
    # to the hardware at this step would be a device translating through an
    # empty table -- default deny working exactly as designed, and the machine
    # losing its disk.
    #
    # The read-back is what checks the *indices*: an entry written at the wrong
    # offset holds entirely correct values, and is a device translating through
    # some other device's tables.
    # Matched to the end of the line, including the two counts, and that is not
    # thoroughness for its own sake: this pattern used to stop at "levels", and
    # a variable shadowing the reserved-region count printed `true refused`
    # into that tail for a whole commit without a single gate noticing. A
    # pattern that stops before a field cannot see that field go wrong.
    if grep -qE "iommu window +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9] [0-9]+-bit, [0-9]+ levels, [0-9]+ reserved pages mapped, [0-9]+ refused" "$LOG"; then
        pass "the device's translation structures are built and verified"
    else
        fail "the IOMMU window was not built, did not read back as written, or reported nonsense"
        status=1
    fi

    # RFC 0043 step 4: every endpoint this kernel cannot drive is passed
    # through, deliberately, and the report says so per device.
    #
    # **The gate is on the words as much as the count.** The RFC's requirement
    # is that "the boot report must name every device that got a window and say
    # which kind it got", because the danger in this answer is a reader seeing
    # "iommu enabled" and believing a device is contained when it reaches all
    # of memory. So the line must carry the device, and must say *not
    # contained* -- a version that printed only a tally would pass a machine
    # that had quietly passed something through.
    #
    # Both endpoints are asserted, not just one: `00:01.0` is a display adapter
    # and `00:1f.3` an SMBus, and a walk that stopped at the first would leave
    # the second absent and its DMA refused, which is the failure this step
    # exists to remove.
    untranslated=$(grep -acE "dma untranslated [0-9a-f]{2}:[0-9a-f]{2}\.[0-9] [0-9a-f]{4}:[0-9a-f]{4} passed through deliberately -- it reaches all of memory, and is not contained" "$LOG")
    if [[ "$untranslated" -eq 2 ]]; then
        pass "both endpoints with no driver are passed through, named, and reported as not contained"
    elif grep -qa "dma untranslated the unit cannot pass devices through" "$LOG"; then
        # The honest other ending: a unit without `ECAP.PT` cannot do this, and
        # the kernel says so rather than falling back silently. No QEMU machine
        # here takes this arm; it is kept so the day one does is not a mystery.
        pass "the unit cannot pass devices through, and the boot says so instead of pretending"
    else
        fail "endpoints with no driver were not passed through (found $untranslated of 2)"
        grep -a "dma untranslated" "$LOG" | sed 's/^/        /' >&2
        status=1
    fi

    # RFC 0012 step 4. The device is handed a `DevAddr` and translation is on
    # before it is programmed, so this asserts the machine finished bring-up
    # with the disk working -- which it cannot do unless every ring and buffer
    # the device was given translates.
    if grep -qE "virtio-blk +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9] [0-9]+ sectors" "$LOG"; then
        pass "the block device works while every address it holds is translated"
    else
        fail "the block device did not come up once its addresses were translated"
        status=1
    fi

    # RFC 0012 steps 4 and 5, in the one demonstration that covers both: a
    # `Memory` object the device can reach, revoked, and then refused to that
    # same device at that same address.
    #
    # One test rather than two because a refused request never completes and
    # leaves the queue unusable -- whichever ran second would find a device
    # that no longer answers and report "nothing refused it" about a machine
    # where nothing had been asked. It is also the sharper assertion: an
    # address the device *had* and lost isolates the page tables from every
    # other reason an access could fail.
    #
    # The assertion is the fault record, deliberately not the request failing.
    # A virtio device completes a request whose data write was refused, so
    # requiring an error tests the driver's plumbing rather than the hardware
    # -- an earlier version did exactly that and reported a protected machine
    # as unprotected.
    # Device-address reuse. Added with the self-test on 2026-08-11 and *not*
    # gated at the time, which an audit the same day caught: the test ran on
    # every IOMMU boot and reported into a log nothing read.
    #
    # The assertion is the second half of the line. That the new object got its
    # sector proves a mapping works; that **the old object's page is untouched**
    # is what proves a freed address stopped translating, and a stale
    # translation writes to the old page and reports nothing.
    if grep -qE "iommu reuse +a device address was freed, handed out again, and translated to the new object -- the old one's page is untouched" "$LOG"; then
        pass "a reused device address translates to the object that owns it now"
    else
        fail "device-address reuse was not reported, or a freed address still translated"
        status=1
    fi

    if grep -qE "iommu memory +an object was reachable at 0x[0-9a-f]+.*revoked, and the device was then refused it" "$LOG"; then
        pass "a revoked object is taken away from the device, not just from the page tables"
    else
        fail "a device kept reaching a revoked object, or the refusal was not reported"
        status=1
    fi

    # RFC 0012 step 6 is **on by default** since 2026-08-11, so this asserts
    # the state and not merely that a state was reported. It was the weaker
    # check until then, because remapping was off and the honest thing to gate
    # was whether the machine said which world it was in.
    #
    # The stronger assertion is affordable now and the weaker one is not: a
    # machine that fell back to unremapped interrupts still boots, still passes
    # every other gate here, and is a machine where a device can raise any
    # vector on any CPU by writing a word. That is precisely the degradation
    # this suite exists to refuse to ship quietly, and only this line sees it.
    if grep -qE "iommu irq +remapping interrupts;" "$LOG"; then
        pass "interrupts are remapped, so a device cannot forge one"
    elif grep -qE "iommu irq +interrupts NOT remapped" "$LOG"; then
        fail "interrupts are NOT remapped -- the machine fell back to RFC 0011's residual risk"
        status=1
    else
        fail "nothing was said about interrupt remapping either way"
        status=1
    fi

    # RFC 0012 step 7: a domain holding a `DmaWindow` may say what a device
    # reaches, and one holding only the memory may not. The refusal is the
    # assertion -- that a domain with both capabilities can map is the easy
    # half, and authority that is ambient rather than held would pass it.
    if grep -qE "iommu grant +a domain mapped its own memory for a device at 0x[0-9a-f]+; the same call without a window capability was refused" "$LOG"; then
        pass "a domain maps for a device only with a window capability"
    else
        fail "delegation is not enforced, or a domain could map without a window"
        status=1
    fi

    # And the machine says the *true* thing about what a device can reach --
    # after enabling, not before.
    if grep -qF "translating: this device reaches only what it was given" "$LOG"; then
        pass "the DMA threat model reported is the one that ended up true"
    else
        fail "translation was enabled and the machine still reports reaching all of memory"
        status=1
    fi
fi

# RFC 0011 step 4: the block driver stops polling. The assertion is a pair of
# counters rather than a duration -- a request on MSI-X spins *never*, and did
# so before the interrupt was claimed. "0 spins" is the number the RFC asks
# for, and a timing measurement on an emulator could not tell the two apart.
#
# The wait count is printed but not asserted. A driver whose device finishes
# before its first completion check waits zero times and is working perfectly;
# requiring at least one wait asserts that the host was slow, which on a loaded
# machine it is not. That version failed a suite run having passed 24 of 24 on
# an idle one.
if grep -qE "virtio-blk irq +msi-x vector 0x[0-9a-f]+; [0-9]+ waits, 0 spins, [1-9][0-9]* interrupts per request" "$LOG"; then
    pass "the block driver never spins, and its interrupt arrives"
else
    fail "the block device is still polling, or its interrupt did not arrive"
    status=1
fi

# RFC 0011 step 5: a domain's death releases the handlers it held. The
# assertion is the *re-claim*, not the release: a release that ran and leaked
# the vector, or left the claim standing, returns success just as loudly, and
# the only thing a later driver needs is to be able to take the source. The
# vector count either side is printed so a leak of one is visible rather than
# inferred.
#
# "skipped" is a pass on a machine whose chip has no such input -- there was no
# handler to release -- and says so in the log rather than counting silently.
if grep -qE "irq teardown +a domain's handler released on its death; gsi [0-9]+ claimed again" "$LOG"; then
    pass "a domain's death releases its interrupt handlers"
elif grep -qE "irq teardown +skipped" "$LOG"; then
    pass "a domain's interrupt teardown was skipped, and said so"
else
    fail "a domain died holding an interrupt handler and the source stayed claimed"
    status=1
fi

# A server may answer the caller it received from, and nobody else. Until RFC
# 0013 step 3 the caller was a number the server passed back, so any thread
# could be sent a message that looked like the reply it was waiting for -- and
# `Reply` is a system call, so ring 3 could do it too. The kernel now remembers
# who a thread received from, which is also what freed the register that made a
# whole four-argument message fit on the server side.
if grep -q "a reply to a thread this one never heard from was refused" "$LOG"; then
    pass "a service cannot answer a caller it never heard from"
else
    fail "the forged-reply refusal was not reported"
    status=1
fi

# What the placement costs, in numbers (RFC 0013 step 5).
#
# The round-trip *count* is asserted here because it is structural: one per
# operation, in either placement, on any machine. The cycle figures are
# reported and not asserted -- a threshold would be a test of whatever machine
# CI runs on, green on a quiet builder and red on a busy one, which is a flaky
# test wearing a performance budget's clothes. The numbers live in the boot log
# and in TRACKER.md, where a change is something a person notices.
if grep -q "1 round trip per operation either way" "$LOG"; then
    pass "the cost of each placement was measured and reported"
else
    fail "no placement cost was measured"
    status=1
fi

# RFC 0017 question 2: a restart policy, in userspace.
#
# `bin/sup` starts a program, waits to be told it ended, reaps it, and starts it
# again -- twelve times. The kernel gained nothing for this: every call it makes
# existed already, which is the claim the RFC wanted tested.
#
# **The count is the assertion, and twelve is the number for a reason.** One
# start proves a spawn; a loop longer than `vm::MAX_SPACES` proves that ending a
# domain gives its address-space slot back, because it cannot finish otherwise.
# Three used to be the number, and three was what exhausted a table of eight and
# left the block driver running with faults nothing would service -- reported,
# for six days, as a fault in the driver. Reaping is asserted too: the envelope
# allows one child at a time, so a supervisor that forgot would get one start
# and a refusal.
if grep -qE "sup: 12 started, 12 ended" "$LOG"; then
    pass "a supervisor in ring 3 started a program, was told it ended, and started it again"
else
    fail "the supervisor did not complete its restarts"
    status=1
fi

# RFC 0032's supervisor interface, and the reason this gate is here rather than
# beside the Linux ones: the five methods exist *because* the Linux personality
# needs to leave the nucleus, and they are worth having only if they are
# generic. So they are proved by `bin/sup` -- a native supervisor that mentions
# Linux nowhere -- reaching into a child it started: mapping a page that was not
# there, writing a word across the domain boundary, scrubbing its own copy, and
# reading the word back out of the child.
#
# The scrub is what makes the round trip mean something: without it the read
# would pass against a copy that did nothing at all.
#
# **The refusals are demanded in the same line as the successes**, because an
# interface that can reach into another domain is only as good as what it will
# not do: an address the child has not mapped, a domain the caller does not
# hold, a copy larger than one page, the same method on a capability that is
# not a domain, and a protection value that does not exist -- the last standing
# in for `W^X`, which has no encoding to ask for.
#
# **Two of those refusals were passing for the wrong reason until this gate was
# armed**, and both are worth recording because they are the failure mode a
# green test hides. The oversized copy ran past the mapping, so it was refused
# for being *unmapped* and the size bound was never reached -- fixed by mapping
# two pages so the length is the only thing wrong with it. And the "not a
# domain" arm was aimed at the console, whose object id names no live domain,
# so deleting the kind check entirely left the gate green; it is aimed at
# `DomainControl` now, whose id is zero, and domain zero is real.
if grep -qE "sup: supervised a running child -- mapped a page into it, wrote a word across, read it back, and was refused an unmapped address, a domain it does not hold, an oversized copy, a capability that is not a domain, a protection that does not exist, and a thread that is not its own" "$LOG"; then
    pass "a supervisor reached into a child it holds, and was refused everything it should be"
else
    fail "the supervisor interface did not hold"
    status=1
fi

# And that the children *ran*, which the supervisor's own counters cannot show.
# Each writes this line through a console capability the supervisor granted it,
# so counting them separates "the supervisor looped" from "the children did
# anything" -- a supervisor that spawned twelve domains and granted nothing would
# report exactly the same twelve starts and twelve endings.
if [[ "$(grep -c '^spawned, hello' "$LOG")" -eq 12 ]]; then
    pass "each restarted child ran and spoke through the capability it was given"
else
    fail "the restarted children did not report, so the grant did not reach them"
    status=1
fi

# The cost of the bulk path, **reported and not asserted**.
#
# The kernel used to require a factor of two here and this comment used to say
# it "fails when shared memory has stopped paying rather than when the builder
# is loaded". That was backwards: measured at eight to ten idle, it fell to 1.74
# with three fuzz campaigns running, and went red three times in one day in a
# subsystem unrelated to the change under test -- once sending an investigation
# into the domain table and producing a wrong diagnosis that reached the remote.
#
# So what is checked now is that the measurement *happened*. The numbers are on
# the record for a person or a soak to watch; a timing assertion needs an idle
# machine and a boot test does not get one.
if grep -qE "bulk cost +[0-9]+ bytes: [0-9]+ cycles shared, [0-9]+ by message" "$LOG"; then
    pass "the bulk path's cost was measured and recorded"
else
    fail "the bulk path's cost was not measured"
    status=1
fi

# Whether this log is complete.
#
# The transmitter drops a byte rather than hang on a UART that will not empty,
# which is the right choice and was a silent one: under an emulator on a loaded
# host a byte went missing from a line of console output, a shell test failed
# on a string that never appeared, and nothing anywhere said a byte had been
# lost. Every other check below reads this log, so this one decides whether
# they are reading all of it.
if grep -q "console out    every byte reached the wire" "$LOG"; then
    pass "no console output was dropped, so the rest of this log is complete"
else
    fail "console output was dropped -- the rest of this log is incomplete"
    grep -E "console out" "$LOG" || true
    status=1
fi

# Configuration space as memory, checked against configuration space as ports.
#
# RFC 0014 step 4, and the reason the port pair was kept rather than replaced:
# it is the oracle. "The new mechanism found three devices" is not evidence
# that it found the right three, so every function on every bus is read both
# ways and the answers must match. `none disagreed` is the assertion; the count
# of functions is there so a run that checked nothing cannot look like a run
# that agreed about everything.
if grep -qE "ecam +0x[0-9a-f]+ for buses [0-9]+\.\.=[0-9]+, [1-9][0-9]* functions read both ways, [0-9]+ present, none disagreed" "$LOG"; then
    pass "configuration space read as memory agrees with the ports, everywhere"
elif grep -qE "ecam +no MCFG" "$LOG"; then
    pass "no MCFG on this machine, so configuration stays on the port pair"
else
    fail "ecam did not agree with the port pair"
    grep -E "ecam" "$LOG" || true
    status=1
fi

# A filesystem this kernel defined, mounted in a machine.
#
# RFC 0015 step 3, and "beside the archive" is literal: the image is a member
# of it. Read-only, and in that order deliberately -- the format is proved by
# reading an image built elsewhere before anything is allowed to write one, so
# a bug in a writer cannot be mistaken for a bug in the reader.
#
# The bytes it reads are in no other file on the machine, and the same name is
# asserted *absent* from the archive: that is what makes this two filesystems
# rather than one read twice.
if grep -qE "filesystem +bhfs mounted from the archive: [0-9]+ blocks, [0-9]+ entries, .greeting. is inode [0-9]+ and reads [1-9][0-9]* bytes that the archive does not have" "$LOG"; then
    pass "an image in this kernel's own format mounts and reads, beside the archive"
elif grep -qE "filesystem +no fs.img" "$LOG"; then
    pass "no image in the archive, so nothing to mount"
else
    fail "the filesystem in this kernel's own format did not mount and read"
    grep -E "filesystem " "$LOG" || true
    status=1
fi

# The block driver is a service now, and something asked it for a sector.
#
# RFC 0015 step 1. The oracle is the image: the Makefile writes
# `BHASKIX-DOMAIN-DISK-SECTOR-0` into sector zero of the disk the *domain*
# drives, so the kernel knows what must come back without being able to read
# that disk itself -- it drives the other one. The refusal is asserted beside
# it, because a service that answers every question is not answering any.
if grep -qE "block service +512 bytes of sector 0 through the service, and they are the domain disk's own; a sector past the end is refused" "$LOG"; then
    pass "a block service in ring 3 answered a request for a sector, and refused one that is not there"
elif grep -qE "block domain +no second device" "$LOG"; then
    pass "no second device, so no block service to ask"
elif grep -qE "block domain +no dma window" "$LOG"; then
    # No unit to contain the device, so the driver was given registers and no
    # way to make it read -- and a service that cannot read a sector cannot
    # answer for one. That is the refusal working, not a service missing.
    #
    # This excuse is only sound because the kernel prints that line from the
    # window's own report. It used to be printed from the `else` of the
    # *interrupt* delegation, which meant a machine that had a window and lost
    # its interrupt could excuse a block service that was genuinely broken.
    pass "no dma window on this machine, so the block service has nothing to answer with"
else
    fail "the block service did not answer for a sector"
    grep -E "block service" "$LOG" || true
    status=1
fi

# RFC 0018 step 2: a network device driven from ring 3.
#
# **Two gates, not one, and that is the point.** A driver that transmits into a
# void and never looks would pass a single assertion covering both directions,
# because transmitting is the half that succeeds whether or not anything is
# listening. Receive is the half that can only pass if a real device really
# wrote into a buffer this driver posted before it asked for anything.
#
# The excuse branch mirrors the block path's: with no unit to contain the
# device there is no address to give it, so the driver reaches the handshake and
# stops. That is the refusal working, and it is the state every BIOS boot is in.
if grep -qE "net frame +transmitted [0-9]+ bytes onto the wire" "$LOG"; then
    pass "a driver in ring 3 put a frame on the wire"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "no network device on this machine, so nothing to drive"
elif grep -qE "net domain +driver reached the handshake and stopped" "$LOG"; then
    pass "no dma window for the network device, so it cannot be driven"
else
    fail "nothing was transmitted"
    grep -E "net domain|net frame" "$LOG" || true
    status=1
fi

# The receive half. Asserted on a *source* that is not this station and not
# broadcast, so a driver that handed back its own transmitted frame -- or an
# empty buffer -- cannot pass. The virtio header length is matched exactly
# because it is a fact this project established by measurement rather than from
# a specification it does not have a copy of; a device model that changed it
# should fail here rather than silently shift every frame by two bytes.
if grep -qE "net frame +received [1-9][0-9]* bytes from 52:55:[0-9a-f:]+, virtio header 12 bytes" "$LOG"; then
    pass "a frame came back from the network and the driver read it"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "no network device on this machine, so nothing to receive"
elif grep -qE "net domain +driver reached the handshake and stopped" "$LOG"; then
    pass "no dma window for the network device, so nothing can arrive"
else
    fail "nothing was received"
    grep -E "net domain|net frame" "$LOG" || true
    status=1
fi

# RFC 0018 step 3: frames crossing from the driver's domain to the protocol
# service's, through a shared ring.
#
# **At least two frames**, not at least one. Written as `([2-9]|[1-9][0-9]+)`
# rather than `[2-9][0-9]*`, which was the first version and which stopped
# matching the moment the count reached ten -- it pins the first digit, so "10"
# fails a test meaning "at least two". A range written as a character class is
# a range that is wrong at the next power of ten. `netd`'s step-2 self-test handled
# exactly one, so a gate satisfied by one could not tell a working receive loop
# from the old behaviour with a ring bolted alongside it — a receive queue that
# is drained and never refilled works precisely once.
#
# The source is matched against QEMU's gateway rather than a wildcard, and it is
# the same address the driver's own report names. That is what makes this a test
# of a frame crossing intact rather than of a counter moving: a ring delivering
# zeroed slots would pass a count and fail this.
if grep -qE "net ring +([2-9]|[1-9][0-9]+) frames crossed to ipd, [0-9]+ bytes, first from 52:55:[0-9a-f:]+, 0 refused" "$LOG"; then
    pass "frames crossed from the driver's domain to the protocol service's"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "no network device on this machine, so nothing to hand across"
elif grep -qE "net ring +nothing crossed; without a dma window" "$LOG"; then
    pass "no dma window, so there are no frames to hand across"
else
    fail "frames did not cross to the protocol service"
    grep -E "net ring|net frame" "$LOG" || true
    status=1
fi

# RFC 0018 step 4a: the return path, gated from **both ends**.
#
# `ipd` says how many frames it built; `netd` says how many it took out of the
# return ring and put on the wire. Two assertions rather than one, because
# "nothing came out" has an end at each side of a ring and a single number
# cannot say which — the ambiguity that cost step 3 an hour of looking at the
# wrong program.
#
# What makes this a test of the *path* and not of a counter: the frame `ipd`
# builds is an ARP request for 10.0.2.3, and `netd`'s own probe asks for
# 10.0.2.2. A request for .3 on the wire can only have been built by a program
# that holds no device, crossed the ring, and been transmitted by one that
# cannot parse it. That is checked by hand with `filter-dump`; what the boot can
# check is the pair of counts.
if grep -qE "net reply +ipd built [1-9][0-9]* frames" "$LOG" &&
   grep -qE "net frame +.*, [1-9][0-9]* sent back for ipd" "$LOG"; then
    pass "the protocol service built a frame and the driver put it on the wire"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "no network device on this machine, so nothing to send"
elif grep -qE "net ring +nothing crossed; without a dma window" "$LOG"; then
    pass "no dma window, so nothing can be sent"
else
    fail "the return path did not carry a frame"
    grep -E "net reply|net frame|net config" "$LOG" || true
    status=1
fi

# RFC 0029 step 3: the second family, end to end on the same wire as the
# first. SLAAC obtained the prefix slirp advertises, a neighbour
# solicitation resolved the v6 host (sticky -- the cache entry itself may
# expire on a busy wire), and an ICMPv6 echo returned byte-for-byte: the
# v4 pongs gate's mirror, one family over, dual stack on one netdev.
# Slirp's IPv6 is on BY DEFAULT here and must stay implicit -- passing
# `ipv6=on` explicitly makes this QEMU's slirp stop answering v4 ARP
# (bisected with a pcap, 2026-08-18); see devices.sh.
if grep -qE "net ipv6 +slaac fec0:0:0:0::/64, router advertised, host resolved by ndp; [1-9][0-9]* v6 echo replies" "$LOG"; then
    pass "ipv6: slaac obtained the prefix, ndp resolved the host, the v6 echo returned"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "ipv6 skipped: no network device on this machine"
elif grep -qE "net ring +nothing crossed; without a dma window" "$LOG"; then
    pass "ipv6 skipped: no dma window"
else
    fail "the ipv6 demonstration did not complete"
    grep -E "net ipv6" "$LOG" || true
    status=1
fi

# RFC 0029 step 4: a datagram out and a datagram in, both through the v6
# socket capabilities, across a real domain boundary twice -- bin/udp6
# sends seventeen bytes from one v6 socket to [::1] and receives them,
# unchanged and correctly attributed, on a second. Loopback rather than
# the network because this QEMU's slirp has no v6 UDP peer at all: the
# resolver has no v6 face and a hairpinned datagram is dropped, both
# measured on the wire with a pcap; an off-box v6 UDP reply carries the
# same written trigger as inbound TCP.
if grep -qE "udp6 client +a v6 datagram crossed to the service and back: two sockets, \[::1\]:[0-9]+ to \[::1\]:[0-9]+, payload returned unchanged" "$LOG"; then
    pass "a v6 datagram crossed both ways through the socket capabilities"
elif grep -qE "net domain +no device on the bus" "$LOG"; then
    pass "udp6 skipped: no network device on this machine"
elif grep -qE "net ring +nothing crossed; without a dma window" "$LOG"; then
    pass "udp6 skipped: no dma window"
else
    fail "the v6 socket demonstration did not complete"
    grep -E "udp6 client" "$LOG" || true
    status=1
fi

# RFC 0020 steps 4 and 5: the TCP domain, against the deterministic peer
# devices.sh provides. The state word is bits -- attached, keyed, configured,
# serving -- and "keyed" means bin/tcpd drew a 128-bit secret from the
# hardware in ring 3: RFC 0021's deliverable consumed by the caller it was
# built for, minting the sequence number the handshake below uses. On a
# machine with a network the demonstration must have COMPLETED: outcome 6 is
# sixteen bytes sent to the guestfwd echo peer and received back unchanged
# with the orderly close under way, and outcome 7 is the same connection
# after TIME_WAIT expired -- a boot long enough to see 2xMSL out. Anything
# less is a failure now, because the peer answers the same way every boot:
# "pending" stopped being weather when the network stopped being one.
#
# On a machine without a network the honest report is state 0x3 and outcome
# 5: the key drawn, no network, said so, serving handovers only. On a machine
# that cannot be unpredictable -- CI's `-cpu qemu64` lanes, which this
# comment once claimed no machine this harness boots could be -- the honest
# report is state 0x1 and outcome 4: never keyed, refusing streams, serving
# handovers only. That arm is accepted *only* when the machine's own feature
# line says `rdrand NO`; outcome 4 on a machine with RDRAND stays exactly the
# failure it always was.
# The echo is demanded outright. This gate briefly carried a third arm that
# accepted a stall in SYN-SENT, while a one-in-three wake loss was being
# hunted; the loss was a thread returning from a notified receive still
# marked blocked (sched::clear_blocked_mark is the fix and carries the story),
# and with it fixed the demonstration completes on every boot that completes.
# A stall here is a regression now, not weather.
# RFC 0022 step 4b moved the echo assertion out of this service: whether the
# payload came back is bin/tcpc's finding now, made against rings it owns and
# gated below. What this service still owes every networked boot is the
# connection itself -- outcome 3, a caller's connection open, or 7 if the
# boot lasted long enough to see TIME_WAIT expire.
if grep -qE "tcpd +state 0xf \(attached/keyed/configured/serving\), outcome (3|7): " "$LOG"; then
    pass "tcp opened a caller's connection against the deterministic peer"
elif grep -qE "tcpd +state 0x3 \(attached/keyed/configured/serving\), outcome 5" "$LOG"; then
    pass "the tcp domain drew its secret, found no network, and said so"
elif grep -qE "rdrand +NO" "$LOG" \
    && grep -qE "tcpd +state 0x1 \(attached/keyed/configured/serving\), outcome 4" "$LOG"; then
    pass "the tcp domain refused to be predictable and said so, still serving handovers"
else
    fail "the tcp service did not open the caller's connection"
    grep -E "tcpd|tcp domain" "$LOG" || true
    status=1
fi

# RFC 0022 step 4: the exchange the RFC exists for, from ring 3, end to end.
#
# bin/tcpc holds two Memory rings its own domain owns and a badged capability
# to the TCP service -- the kernel wires *nothing* between the two programs.
# The client hands one ring across each of two CONNECT calls (one capability
# per call, as the RFC's alternatives table records), then declares a slot
# with EXPECT and asks; the connection capability the service minted rides
# the reply into that slot. The gate demands the terminal success, and it is
# unconditional: the handover needs no network, and the service now serves it
# even on a machine that has none -- which is itself part of the change,
# because the old no-network path exited and left the endpoint dead with
# every future caller queued against it.
# Step 4b: the gate's success arm is the stream, not just the handover. On a
# networked boot the payload must leave through the client's own send ring
# and return through its own receive ring unchanged; on a machine with no
# network the connection capability must still answer, saying unreachable --
# the truthful ending there, and still proof the whole exchange worked.
# ...and step 5's whole answer: on a networked boot the client must have
# echoed outbound AND accepted the host driver's inbound connection, served
# its echo, and seen the peer close -- with the *host side* agreeing, through
# the verdict file its driver wrote only if the sixteen bytes came back
# byte-for-byte. Guest-side and host-side are asserted together because
# either alone can lie: a guest that believes it served proves nothing about
# what crossed the boundary, and a lucky reply with a wedged guest report
# would hide a real stall.
# RFC 0020 step 6: the measurement must have happened on a networked boot.
# The numbers are recorded, not gated -- a slow host is not a broken kernel --
# but a networked boot that produced none measured nothing, and that is a
# failure of the instrument.
# RFC 0031 interface I1, as a ratchet. The nucleus is meant to carry a
# foreign call's number without interpreting it; it interprets eighteen. The
# count is printed on every boot that ran a hosted program, and this gate
# lets it *shrink* and never grow -- so the boundary violation is a number
# with a direction rather than a paragraph in an RFC.
#
# **It reached zero on 2026-08-20** (RFC 0032 step 10), so the ratchet is now
# an equality: eighteen, then seven, then two, then none, and the gate that
# allowed a fall no longer allows anything else. A number here again is a
# Linux concept back in the nucleus, which is the thing RFC 0031 exists to
# prevent -- and it is caught on the next boot rather than in review.
#
# The cost figure beside it is the other half of RFC 0031's requirement: the
# in-nucleus placement priced *before* the move, with the instrument the
# domain placement will be priced by. It is reported and not gated -- a
# threshold on a cycle count measured under an emulator would be a gate on
# the host's load, which is the mistake `docs/coding-style.md` warns about
# and which this suite has made before.
if grep -qE "personality +boundary: [0-9]+ linux numbers interpreted in the nucleus" "$LOG"; then
    interpreted=$(sed -n 's/.*boundary: \([0-9]*\) linux numbers.*/\1/p' "$LOG" | head -1)
    if [[ "$interpreted" -eq 0 ]]; then
        pass "the nucleus interprets no linux number at all, and this gate holds it there"
    else
        fail "the nucleus interprets $interpreted linux numbers -- it reached 0 on 2026-08-20 and RFC 0031 I1 keeps it there"
        status=1
    fi
    # And the instrument accounts for itself. Every foreign call is priced,
    # excluded as blocking, or dropped as preempted, and the three must sum
    # to the total -- which is how the first version was caught reporting a
    # confident mean over 7 of 212 calls, because `exit` never returns to be
    # priced and the exclusions were being counted on the way out. A cost
    # figure whose population is unstated is not a measurement.
    if grep -qE "personality +boundary:.* all [0-9]+ of [0-9]+ accounted" "$LOG"; then
        pass "the boundary instrument accounts for every foreign call it priced"
    else
        fail "the boundary instrument left foreign calls unaccounted for -- its cost figure is over an unstated population"
        status=1
    fi
else
    # Not every machine runs a hosted program: a boot with no foreign call
    # has no boundary to report, and demanding the line there would gate on
    # the machine rather than on the kernel.
    pass "no hosted program on this machine, so the boundary had nothing to report"
fi

# RFC 0032 step 3: the personality, in ring 3, answering a real hosted program.
#
# This is the gate the whole relocation is for. `bin/linuxd` holds **one
# endpoint and nothing else** -- not even a console -- and a foreign call the
# nucleus does not answer is delivered to it as an ordinary IPC call made by
# the hosted thread itself, which blocks until the reply.
#
# What makes it evidence rather than plumbing: `getpid` was *removed* from the
# nucleus in the same change, so the pid a hosted program reads now comes from
# a program in ring 3 -- and the personality self-test above demands a pid that
# is a small positive number, which an `-ENOSYS` is not. Both gates have to
# hold at once for this to pass, and neither can be satisfied by the other.
#
# The count is demanded to be non-zero rather than exact: how many calls fall
# through to the adapter depends on which self-tests a machine could run.
if grep -qE "linux domain   the adapter in ring 3 answered [1-9][0-9]* foreign calls, and 0 found none to ask, 0 were refused by its endpoint, 0 gave up" "$LOG"; then
    pass "the linux personality answered a hosted program from ring 3, holding one endpoint"
elif grep -qE "linux domain   the adapter in ring 3 answered" "$LOG"; then
    # The line itself, because a gate that says only "it did not hold" sends
    # the next reader back for another boot to find out which of four numbers
    # was wrong -- and under a full suite the serial log is a temporary file
    # that is already gone. Three of those numbers want different repairs: an
    # adapter that was not there is a boot-order bug, one whose endpoint
    # refused is a dead adapter, and one that gave up retrying is a machine
    # under load.
    fail "the adapter was asked and did not answer: $(grep -aoE 'the adapter in ring 3 answered.*' "$LOG" | head -1)"
    status=1
else
    pass "no hosted program on this machine, so the adapter had nothing to answer"
fi

# RFC 0032 step 6: a hosted program's *fault* reaching the personality.
#
# This is the crossing that could not be made until two facts were
# established, both of them in the code rather than in an opinion: the page
# fault is deliberately not on an IST, so it runs on the faulting thread's own
# kernel stack and blocking preserves its frame; and it arrives through an
# interrupt gate with the mask up, so interrupts must be enabled before
# anything blocks or the CPU goes deaf to the tick that would resume it.
#
# What the gate demands is that a fault was *handed over* -- the kernel wrote
# the register file into a slot, called `bin/linuxd`, and got an answer back.
# It does not demand a resume: while `rt_sigaction` still lives in the nucleus
# the adapter does not own the dispositions, so every fault it sees is one
# nothing wanted, and `0 resumed` is the correct answer rather than a
# shortfall.
# **Keyed on a fault having happened, not on the crossing being reported.**
# The first version asked only whether the crossing line was present, and
# disabling the crossing entirely made it fall into the "nothing faulted"
# branch and pass -- the third arm in this suite to have that shape, and the
# third to be found by deliberately breaking what it guards. A hosted program
# that faults says so in its own line whatever happens next, so that line is
# what decides which question this gate asks.
if grep -qE "linux fault    a hosted program faulted at" "$LOG"; then
    if grep -qE "linux fault    [1-9][0-9]* faults handed to the personality in ring 3, [0-9]+ resumed, 0 found no free slot" "$LOG"; then
        pass "a hosted program's fault crossed to ring 3 and was decided there"
    else
        fail "a hosted program faulted and the personality never saw it: $(grep -aoE 'linux fault    [0-9]+ faults handed.*' "$LOG" | head -1)"
        status=1
    fi
else
    # No hosted program faulted on this machine -- the corpus needs a
    # filesystem to load from, and a lane without one has nothing to fault.
    pass "no hosted program faulted on this machine, so nothing crossed"
fi

# RFC 0005 step 6, the clone half: two threads of one hosted program, meeting
# through a futex. This is the gate that could not exist while clone was
# refused -- one thread cannot prove that a wait blocks and a wake releases
# it, and the RFC is explicit that a subtly wrong futex produces a deadlock
# under load rather than an error.
#
# `woke 1` is demanded and not relaxed, because it is the only word in that
# sentence that says the parent actually *slept*. A run where the child wins
# the race reports `wait 0, woke 0` -- which is correct behaviour and no
# proof of anything -- so the self-test detects that case and runs the whole
# rendezvous again rather than reporting it as success. Seen once in a full
# suite on 2026-08-19, on a kernel that had done nothing wrong.
if grep -qE "linux clone +a Linux program cloned a thread \(tid [1-9][0-9]*, which the child agrees is its own\), then the two met through a futex: the parent slept, the child set the word to 42 and woke 1, and the parent came back; the parent then parked in a futex and the child.s exit_group ended them both" "$LOG"; then
    pass "clone makes a real thread, and the futex pairs a sleeper with a waker"
else
    fail "the Linux clone self-test did not conclude"
    status=1
fi

# RFC 0005 step 6: the futex contract's edges, which is where the RFC says a
# subtle mistake does not produce an error but a deadlock under load. A WAIT
# whose word has already changed must refuse to sleep; a WAKE with nobody
# asleep must wake none; a shared futex and a clone are refused with reasons.
# And RFC 0032 step 10's `write`: **both halves are demanded**, because
# neither can stand alone. The count says the adapter answered sixteen; the
# string says those sixteen bytes reached the machine's console out of a
# `Console` capability held in ring 3. A count with no string would pass on an
# adapter that answered and printed nothing. The string is matched without an
# anchor on purpose: the adapter puts **one character per invocation**, so
# where the line begins depends on what the console was in the middle of --
# a real property of a console that is a capability, recorded in RFC 0032
# rather than hidden by a stricter pattern here. No kernel path prints these
# bytes; they live in the hosted program's own page.
#
# The tail of the same sentence is RFC 0032 step 9's: `arch_prctl` is answered
# by a program in ring 3 now, which sets a *hosted* thread's TLS base from
# outside that thread. The witness value read back through `fs:[0]` is what
# says the base reached the thread it named rather than the CPU the adapter
# happened to run on -- a distinction an answer of zero cannot make.
if grep -qE "linux futex +a Linux program asked its tid \([1-9][0-9]*\) and pid \([1-9][0-9]*\), yielded, and met the futex contract's edges" "$LOG" \
    && grep -qE "then it set its TLS base, read 0x5afe back through it, and wrote 16 bytes to the console through the adapter" "$LOG" \
    && grep -qF "hosted write ok" "$LOG"; then
    pass "the futex contract holds at its edges, and the identity, TLS and write calls answer"
else
    fail "the Linux futex self-test did not conclude"
    status=1
fi

# RFC 0005 step 5: the memory calls over the region map -- which already
# makes W^X unrepresentable, so a request for both is refused rather than
# quietly downgraded. The probe writes into the *second* page of what it
# mapped, so the lazy commit has to reach past the first, and unmaps.
if grep -qE "linux memory +a Linux program mapped two anonymous pages at 0x[0-9a-f]+, wrote and read 42 in the second" "$LOG"; then
    pass "a Linux program maps, uses and unmaps memory through the region map"
else
    fail "the Linux memory self-test did not conclude"
    status=1
fi

# RFC 0036 step 2's measurement, printed on every boot that runs a hosted exec.
# The RFC's question 1 -- who chooses a hosted program's load address -- turns
# on whether the adapter could load an image itself through the supervisor
# interface, and that turns on this number. The gate asserts the line exists and
# carries three figures; it deliberately does **not** assert a threshold,
# because the numbers are TCG and a bound on an emulator's arithmetic would be a
# gate about QEMU. What must not happen is the measurement disappearing.
if grep -qE "linux copyout +a page through COPY_OUT costs [0-9]+ cycles the first time and [0-9]+ warm, in [0-9]+ crossings; the kernel moves a page through the direct map in [0-9]+" "$LOG"; then
    pass "the cost of a supervised copy is measured against the kernel's own"
else
    fail "the supervised-copy measurement did not appear"
    status=1
fi

# `security.md` §1 gap 3: a hosted process's `mmap` region is drawn per process
# rather than bumped from one shared counter at a fixed base. The software
# arriving under L1-L4 is C, and a hosted process at a wholly predictable layout
# turns any bug in it into a reliable exploit rather than a crash.
#
# **The condition matters and is stated rather than assumed.** The draw is
# `RDRAND`, and a machine without it gets the floor -- `bin/linuxd` falls back
# rather than refusing to run a program, because a layout is a hardening measure
# and not a correctness one. Every machine this harness boots reports `rdrand`
# present, so the drawn arm is the one asserted here; on a machine without it
# the kernel prints the other line, in yellow, saying the layout is known. What
# is refused is silence: a boot that says neither has stopped reporting.
#
# Negative-armed by construction rather than by editing: the address printed is
# the one the hosted program received, and three consecutive boots on 2026-08-21
# gave 0x707c9b39a000, 0x70b501870000 and 0x70718f4f2000 -- so a build that
# stopped drawing would print the floor and fail this line without anything
# being made wrong on purpose.
if grep -qE "linux aslr +the hosted mmap base was drawn, not fixed: 0x[0-9a-f]+, 28 bits" "$LOG"; then
    pass "a hosted process's memory layout is drawn, not fixed"
elif grep -qE "linux aslr +the hosted mmap base is the floor" "$LOG"; then
    pass "this machine drew no entropy, and the boot says the hosted layout is known"
else
    fail "the boot said nothing about the hosted memory layout"
    status=1
fi

# RFC 0005 step 4: signals, the part the RFC says to build first because it
# is where the design is most likely to be wrong. A Linux program installs a
# SIGSEGV handler, faults on purpose, reads cr2 out of the ucontext it was
# handed, edits the saved rip, and returns through rt_sigreturn -- which is
# precisely how Go turns a null dereference into a recovered panic. Every
# link is load-bearing: a wrong ucontext offset reads the wrong field, a
# wrong rip slot resumes into the fault again, a broken sigreturn never
# resumes at all.
if grep -qE "linux signal +a Linux program faulted on purpose, its SIGSEGV handler read cr2 0x0 out of the ucontext, edited the saved rip, and rt_sigreturn resumed it where it said: 1 delivered, 1 returned" "$LOG"; then
    pass "a Linux fault becomes a signal, and the handler's edit takes effect"
else
    fail "the signal round trip did not complete"
    status=1
fi

# RFC 0005 step 3: the initial process image. A Linux program walks the
# stack this kernel built -- argv, envp, the auxiliary vector -- and finds
# the entropy AT_RANDOM promised, which Go's runtime treats as not optional.
# The builder itself is host-tested byte for byte; this is the proof that a
# program reading it the way Go does finds what was put there.
if grep -qE "linux stack +a Linux program walked the initial image this kernel built: argc 2, AT_ENTRY 0x[0-9a-f]+, and the sixteen AT_RANDOM bytes it found are the entropy" "$LOG"; then
    pass "a Linux program reads the initial image, auxiliary vector and all"
else
    fail "the initial-image self-test did not conclude"
    status=1
fi

# RFC 0005 step 2: the personality tag exists and refuses. A Linux-tagged
# domain's every system call is foreign -- answered ENOSYS, logged with its
# number -- the tag is refused once a thread exists, and it dies with the
# domain. The self-test asserts the exact sequence its probe issued; this
# gate asserts the self-test ran and concluded.
#
# RFC 0031 §6's Test 1, in the arm this probe funds: the same program asks
# for all five of this kernel's own syscall kinds *by number* -- 0 Invoke,
# 2 Reply, 3 Recv, 4 Yield, 5 Exit, each also an ordinary Linux call this
# personality does not answer -- and is answered five times with a *Linux*
# errno. The survival clause is the load-bearing half and is demanded here
# rather than left to the self-test's own arithmetic: read in the native
# dialect, 5 is Exit and the probe would not have lived to report anything
# after it.
#
# **It said "-ENOSYS five times" until 2026-08-20**, which was true only while
# this personality answered none of those numbers. RFC 0033 step 6 gave three
# of them meanings -- 0, 2 and 3 are `read`, `open` and `close` -- so the claim
# is now that every answer is *small and negative*, which no native status is,
# and that the probe lived. Both are stronger than the old form: `-9` from
# `read` is the personality refusing a descriptor, and a native `Recv` would
# have blocked rather than answering at all. A hosted
# program holds no capabilities and cannot name one, so a number read in the
# wrong dialect is the only route it could ever have had to the capability
# interface.
if grep -qE "personality +a Linux-tagged domain asked getpid, write and exit: the pid answered, the bad descriptor refused EBADF, and exit never came back; it then asked for all five of this kernel's own syscall kinds by number and got a Linux errno five times, surviving the one that is Exit natively; [1-9] foreign calls logged in order" "$LOG"; then
    pass "a Linux program is refused in Linux's dialect, and cannot reach the native one by number"
else
    fail "the personality self-test did not conclude"
    status=1
fi

if grep -qE "tcp client +echoed outbound" "$LOG" && ! grep -qE "tcp measure +handshake [0-9]+ us" "$LOG"; then
    fail "the networked boot produced no TCP measurement"
    status=1
fi

# RFC 0029 step 6: the second family measures itself the same way -- and
# because the loopback peer is the program's other half, these numbers carry
# no emulator at all. Same discipline: recorded, not gated on magnitude, but
# a boot whose v6 act completed without producing them measured nothing.
if grep -qE "tcp client +did everything outcome 9 says" "$LOG" \
    && ! grep -qE "tcp measure6 +loopback handshake [0-9]+ us" "$LOG"; then
    fail "the v6 loopback act completed but produced no measurement"
    status=1
fi

# RFC 0029 step 5 raised the terminal: after both v4 directions, the same
# program opens a v6 connection to [::1], accepts it with its own listener,
# and echoes itself through the loopback -- the whole machine, both roles,
# second family. On networked lanes that ending is now the demanded one.
if grep -qE "tcp client +did everything outcome 9 says, then opened a v6 connection" "$LOG"; then
    if [[ -f "$INBOUND_VERDICT" ]]; then
        pass "both directions: outbound echoed, and a host-initiated connection was accepted and served"
        rm -f "$INBOUND_VERDICT"
    else
        fail "the guest says it served the inbound echo; the host driver never got its bytes back"
        status=1
    fi
elif grep -qE "tcp client +holds a working connection capability on a machine with no network" "$LOG"; then
    if [[ -f "$INBOUND_VERDICT" ]]; then
        fail "a machine reporting no network answered the host driver anyway"
        rm -f "$INBOUND_VERDICT"
        status=1
    else
        pass "no network, but the handover completed and the connection capability answered honestly"
    fi
elif grep -qE "rdrand +NO" "$LOG" \
    && grep -qE "tcp client +holds a working connection capability on a machine that cannot be unpredictable" "$LOG"; then
    # The second dark arm, keyed like the service's: only a machine whose own
    # feature line says `rdrand NO` may end this way, and it must not have
    # served the host driver -- a service refusing to mint sequence numbers
    # has no business completing a connection.
    if [[ -f "$INBOUND_VERDICT" ]]; then
        fail "a machine refusing entropy answered the host driver anyway"
        rm -f "$INBOUND_VERDICT"
        status=1
    else
        pass "no unpredictability, but the handover completed and the connection refused its stream honestly"
    fi
else
    fail "the ring handover or the stream through it did not complete"
    grep -E "tcp client" "$LOG" || true
    status=1
fi
rm -f "$INBOUND_VERDICT" 2>/dev/null || true

# RFC 0047: a port nobody holds says so.
#
# The property is not "the connection failed" -- it is that the *machine
# answered*. A peer that hears nothing cannot tell a closed port from a lost
# packet and retransmits for its whole connect timeout; a peer that hears a
# `RST` stops at once. That difference is measured here as a read that returns
# within three seconds carrying nothing.
#
# Three arms, and the third is why the probe waited on the inbound driver
# rather than racing the boot: if no inbound connection was ever served, the
# probe never ran, and the gate above has already said why. Two lines of red
# for one fault sends the reader looking for a second bug.
if [[ -f "$CLOSED_VERDICT" ]]; then
    closed_said=$(cat "$CLOSED_VERDICT" 2>/dev/null || true)
    rm -f "$CLOSED_VERDICT"
    if [[ "$closed_said" == "refused" ]]; then
        pass "a connection to a port no listener holds was refused, and refused promptly"
    else
        fail "a port nothing holds answered the probe -- $closed_said"
        status=1
    fi
elif grep -qE "tcp client +did everything outcome 9 says, then opened a v6 connection" "$LOG"; then
    fail "the machine served an inbound connection but never refused one to a closed port"
    echo "        a peer connecting to a shut port here hangs until its own timeout" >&2
    status=1
else
    pass "closed-port refusal not attempted: no inbound connection was served (see above)"
fi
rm -f "$CLOSED_VERDICT" 2>/dev/null || true

# RFC 0013 step 6: a block driver in ring 3, driving a device of its own.
#
# The kernel enumerates the bus -- PCI configuration space is port I/O, and a
# domain holding that would hold every device on the machine -- and hands over
# three `Frame` capabilities and a `Memory` object. Everything after that is
# the driver's: it maps its own windows, resets the device, and drives the
# handshake to 3 (acknowledge, driver).
#
# `1 sectors` is the assertion that matters. That is the domain's own disk; the
# kernel's is 180. A driver handed the wrong device says so in a number nothing
# else on this machine produces.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    # With a unit to contain it, the driver is given a DMA window and is
    # expected to have *read the disk*: status 15, and the first bytes of
    # sector zero off its own image. `BHASKIX-` is on that disk and on no
    # other, so a driver reading the kernel's device, or reading nothing and
    # reporting a zeroed page, says so.
    # `woken by the device` is the part that took the longest to be true: the
    # kernel programmed the MSI-X entry, the driver said which entry its queue
    # uses, and the completion arrived as a notification rather than as
    # something the driver noticed by looking.
    if grep -qE 'block domain +ring 3 driver: .*drove it to 15, .*512 sectors, sector 0 begins "BHASKIX-", woken by the device, and says it is 1af4:1042 from its own configuration space' "$LOG"; then
        # `1af4:1042` is the virtio vendor and the modern block device, read
        # by the driver out of its *own* configuration space with no help from
        # the kernel. It is only reported when the same page was **refused** a
        # writable mapping, so one value covers both halves of RFC 0014's
        # decision: configuration space is readable and never writable, because
        # a writable configuration page is a writable BAR.
        pass "a driver in ring 3 read its disk, was woken by its interrupt, and named its own device"
    else
        fail "the block driver in a domain did not read its disk"
        grep -E "block domain" "$LOG" || true
        status=1
    fi
elif grep -qE "block domain +ring 3 driver: .*drove it to 3, .*512 sectors" "$LOG"; then
    # Without a unit the driver gets registers and no window, so it brings the
    # device up and stops. That is the refusal, not a shortcoming: a domain
    # that could aim a device with physical addresses would be a domain that
    # could aim it at the kernel.
    pass "a driver in ring 3 brought up a device it was given no way to make read"
else
    fail "the block driver in a domain did not report a device it had driven"
    grep -E "block domain" "$LOG" || true
    status=1
fi

# RFC 0013: the services run behind a trait, and the machine names them with
# their placement. The placement is the claim `architecture.md` §2 makes, so it
# is printed rather than assumed -- and this line is expected to change at step
# 3, when one of these stops saying `nucleus`. A line that can never change is
# a line worth distrusting, which this milestone has now learned nine times.
#
# Step 2 makes it say something harder: the line must agree with
# `services.toml`, which is the file that is supposed to decide placement.
# Built from the table rather than written out here, so that a table nobody
# reads and a machine nobody checked cannot drift apart while both look right.
expected=$(awk '
    /^name *=/     { gsub(/[" ]/, ""); sub(/^name=/, ""); name = $0 }
    /^placement *=/ { gsub(/[" ]/, ""); sub(/^placement=/, ""); printf "%s%s=%s", sep, name, $0; sep = " " }
' "$(dirname "$0")/../../services.toml")

# An override changes what the machine was *built* to do, so it changes what
# this gate should expect -- otherwise testing the other placement would mean
# editing the table, and a test that edits the file it is testing is not
# testing it. The comparison stays real: the line still comes from what the
# machine did, and only the expectation moves.
if [[ -n ${BHASKIX_PLACEMENT_VFS:-} ]]; then
    expected=$(sed "s/vfs=[a-z]*/vfs=$BHASKIX_PLACEMENT_VFS/" <<<"$expected")
fi
if [[ -n ${BHASKIX_PLACEMENT_CONSOLE:-} ]]; then
    expected=$(sed "s/console=[a-z]*/console=$BHASKIX_PLACEMENT_CONSOLE/" <<<"$expected")
fi

if [[ -z $expected ]]; then
    fail "services.toml lists no services, so the placement gate would check nothing"
    status=1
elif grep -qF "placement      $expected, dispatched by message" "$LOG"; then
    pass "the machine's placement matches services.toml ($expected)"
else
    fail "placement disagrees with services.toml (expected: $expected)"
    grep -E "placement" "$LOG" || true
    status=1
fi

# One address space per user program, and the count says how many. This was one
# for the whole of M5 and M6 -- the kernel kept a single installed space, which
# with one user program at a time is indistinguishable from keeping the right
# one, and nothing reported it. Two services in their own domains landed on one
# CPU and ran in each other's page table.
#
# The expectation is derived rather than fixed: the shell always has one, and
# each service placed in a domain is another program with its own memory. A
# fixed number would have to be wrong in three of the four placements.
#
# **And how many are left**, which RFC 0033 step 3 makes a gate rather than a
# curiosity: a hosted Linux process is a domain with an address space of its
# own, so the free count is the number of them this machine can still hold.
# It read five before that step raised the table. Demanded to be at least
# eight so that a shell pipeline's worth of hosted processes fits, and so that
# a future service quietly consuming the headroom is caught here rather than
# by an eleventh program faulting in a space that could not be installed.
domains=$(grep -o "=domain" <<<"$expected" | wc -l)
want=$((1 + domains))
spaces=$(sed -n 's/.*address spaces \([0-9]*\) of [0-9]* in use at once.*/\1/p' "$LOG" | tail -1)
free=$(sed -n 's/.*address spaces [0-9]* of [0-9]* in use at once[^(]*(\([0-9]*\) free).*/\1/p' "$LOG" | tail -1)
if [[ -n $spaces ]] && ((spaces >= want)) && [[ -n $free ]] && ((free >= 8)); then
    pass "each user program has an address space of its own ($spaces, wanted $want; $free free for hosted processes)"
else
    fail "wanted at least $want address spaces in use and 8 free, found ${spaces:-none} used and ${free:-none} free"
    status=1
fi

# RFC 0033 step 10: `/proc`, and what a hosted program may learn about itself.
#
# The probe maps a page and then prints `/proc/self/status` and
# `/proc/self/maps`. What is demanded is the **maps line for the page it just
# mapped** -- the personality's own region list, written back in Linux's format
# to the program that made it. If the two disagreed about where that page is,
# the line would say so; if the file were never read, there would be no line.
#
# **The leak half of this step is not here, and cannot be.** A boot gate can
# only look for what somebody thought to forbid. The check that matters is a
# host test in `personality::proc` which enumerates the field names this
# personality may publish and fails on any other -- it looks for anything not
# explicitly allowed, which is the shape a leak has.
if grep -qE "^0000000052000000-0000000052001000 rw-p" "$LOG" \
    && grep -qE "^Pid:" "$LOG"; then
    pass "a hosted program read /proc about itself, and its map says where its own page is"
elif grep -qF "linux proc     skipped" "$LOG"; then
    pass "no second cpu, so the /proc test was skipped"
else
    fail "the /proc test did not conclude: $(grep -aoE 'linux proc .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0033 step 9: `wait4`. Two witnesses, and the number is the same in both.
#
# The child ends with `exit_group(7)`. The adapter's record says which child was
# collected and the **status word** it handed back -- `0x700`, which is Linux's
# encoding of "exited, status 7". And the parent decodes that word itself and
# prints `s=7`, which is the byte the child put in its register travelling all
# the way back through a record, a wait and a shift.
#
# A `wait4` that invented a status would print `s=0` -- which is exactly what
# the record held before this step, so the number is what separates a `wait4`
# that works from one that merely returns.
if grep -qE "linux wait     a Linux program forked, its child ended, and the parent collected pid [1-9][0-9]* with status word 0x700" "$LOG" \
    && grep -qF "s=7" "$LOG"; then
    pass "a parent collected its child's exit status, and read the number the child chose"
elif grep -qF "linux wait     skipped" "$LOG"; then
    pass "no second cpu, so the wait test was skipped"
else
    fail "the wait test did not conclude: $(grep -aoE 'linux wait .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0033 step 8: `fork`, by copying. Two things, and the second is the one a
# fork that "worked" could not fake.
#
# The adapter says how many bytes it moved -- the number the whole step exists
# to produce, because RFC 0033 writes copy-on-write as something to build only
# if a measurement asks for it. And the **child** prints what its parent wrote
# before forking, out of its own address space: a fork that made a domain and
# started a thread but copied nothing would print zeros, and one that shared the
# page rather than copying it would be a different bug that this probe cannot
# tell apart -- which is why the parent writes and only the child reads.
if grep -qE "linux fork     a Linux program forked: the child is pid [1-9][0-9]*, [1-9][0-9]* bytes of its parent's memory were copied" "$LOG" \
    && grep -qF "copied!" "$LOG"; then
    pass "a hosted program forked: its child ran, in its own copy of its parent's memory"
elif grep -qF "linux fork     skipped" "$LOG"; then
    pass "no second cpu, so the fork test was skipped"
else
    fail "the fork test did not conclude: $(grep -aoE 'linux fork .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0033 step 7: two hosted threads meet through a pipe, and the *blocking*
# half is what this gate is for. The reader finds the pipe empty and parks --
# which the kernel counts, because only a `BLOCK_ON` reply increments that
# counter and the only call in this probe that can produce one is a read of an
# empty pipe. Then the writer wakes it and the bytes cross.
#
# Both halves are demanded: the report line, and the message itself on its own.
# A reader told "end of file" instead of parking would print nothing and the
# message would be missing; a reader never woken would hang and its domain would
# never end. Neither failure can produce this pair.
if grep -qE "linux pipe     two hosted threads met through a pipe: the reader parked on an empty one, the writer woke it, and .through a pipe. crossed \(attempt [1-4]\)" "$LOG" \
    && grep -qE "^through a pipe" "$LOG"; then
    pass "a pipe joined two hosted threads: the reader blocked, the writer woke it, the bytes crossed"
elif grep -qF "linux pipe     skipped" "$LOG"; then
    pass "no second cpu, so the pipe test was skipped"
else
    fail "the pipe test did not conclude: $(grep -aoE 'linux pipe .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0033 step 6: a hosted program opens a real file and prints what it read.
#
# **Two arms, and the dark one is the ordinary case here.** This lane has no
# block service, so there is no filesystem service, so the adapter is granted no
# directory and a hosted program has nothing to open. The lane that proves the
# bright arm is `shell-test.sh disk`, where the filesystem comes off the device.
#
# What the bright arm demands is the file's *contents* -- a line the filesystem
# was built with, which no part of the personality could invent -- beside the
# adapter's own account of which descriptor it handed out and how many bytes it
# read.
if grep -qE "linux file     a Linux program opened a file through the adapter's directory, read [1-9][0-9]* of its [0-9]+ bytes" "$LOG"; then
    if grep -qF "only reachable through the subdirectory" "$LOG"; then
        pass "a hosted program read a real file through a capability the adapter holds"
    else
        fail "the adapter says it read a file, but its bytes never reached the console"
        status=1
    fi
elif grep -qF "linux file     skipped: this machine has no filesystem service" "$LOG"; then
    pass "no filesystem service on this machine, so hosted programs have no files to open"
else
    fail "the hosted file test did not conclude: $(grep -aoE 'linux file .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0005 step 8: a hosted program lists a directory, stats a file and seeks
# inside it.
#
# **Three strings, none of which the personality can produce on its own**, and
# each is a different call's evidence:
#
# **One name printed three times, and each printing is a different call.** The
# probe writes `inner` -- an entry read out of the filesystem image, which no
# part of the personality could invent -- once per proof:
#
#   1. `getdents64` on the directory the process was given. Until this step
#      that directory could not be opened at all.
#   2. `lseek(dirfd, 0, SEEK_SET)` and `getdents64` again. Only the seek makes
#      the second one answer: a spent listing returns nothing, and the probe
#      stops with the name printed once.
#   3. `fstat(dirfd)`, printed only when `st_mode` says directory -- so a
#      mode at the wrong offset of the `struct stat` stops the probe here.
#   4. `close(dirfd)` then `open("inner")` -- the close guard: the directory's
#      handle is the adapter's own root capability, and a `close` that
#      released it leaves this open with nothing to find.
#
# So the gate is the name four times running, and counting is the check --
# three would be a stat that worked and a close that took the filesystem
# away with it.
if grep -qE "linux dir      a Linux program listed the directory it was given" "$LOG"; then
    if ! grep -qF "inner" "$LOG"; then
        fail "the directory was listed and no entry name reached the console"
        status=1
    elif ! grep -qF "innerinnerinnerinner" "$LOG"; then
        fail "the listing worked but the seek or the stat did not -- printed \
$(grep -aoE 'inner(inner)*' "$LOG" | head -1) where innerinnerinnerinner was due"
        status=1
    elif [ "$(grep -acF "only reachable through the subdirectory" "$LOG")" -lt 2 ]; then
        # **The end-to-end half of RFC 0044, and it is a count rather than a
        # match.** The `linux file` probe reads that line, and so does this
        # one -- so the text appearing *once* is the old behaviour, where a
        # hosted program could read one file per machine and the second
        # `ATTACH` was refused at an address nothing appeared to be using.
        # Twice is the property: revocation gave the address back.
        fail "only $(grep -acF "only reachable through the subdirectory" "$LOG") hosted read(s) \
reached the console; two hosted programs read a file and both must"
        status=1
    elif ! grep -qF "Linuxx86_64x86_64" "$LOG"; then
        # The rest of Tier 1's file surface, in one string, and the *count*
        # is the check:
        #
        #   `Linux`   -- `uname`'s sysname. It says which ABI this is, which
        #                is the question the field asks; `release` and
        #                `version` say what the system actually is, and a
        #                host test holds them to naming Bhaskix.
        #   `x86_64`  -- printed once because `ioctl(1, TCGETS)` succeeded on
        #                the console, which is what `isatty` reads...
        #   `x86_64`  -- ...and once more because the same request on the
        #                *file* was refused. One marker rather than two is an
        #                adapter that calls every descriptor a terminal, and
        #                every program that redirects its output asks this.
        fail "uname or the ioctl allow-list did not answer: $(grep -aoE 'Linux[a-z0-9_]*' "$LOG" | head -1)"
        status=1
    else
        pass "a hosted program read a second file, asked uname, and found only its console is a terminal"
    fi
elif grep -qF "linux dir      skipped" "$LOG"; then
    pass "no filesystem service on this machine, so hosted programs have no directory to list"
else
    fail "the hosted directory test did not conclude: $(grep -aoE 'linux dir .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0033 step 5: `execve`. Three things have to be true at once, and no two
# of them come from the same place.
#
#   1. The execing program's own domain **ended** -- the kernel watched its
#      thread count reach zero, which is what the adapter's `END_DOMAIN` reply
#      asks for and nothing else in the machine does.
#   2. `bin/linuxd` says which pid it kept and which two domains it kept it
#      across, out of its own report page.
#   3. The program that was exec'd asked `getpid` **in the new domain** and
#      printed the answer to the console.
#
# The gate demands that (2) and (3) name the *same* pid and that the two domains
# in (2) differ. A pid derived from a domain could not satisfy that pair, which
# is the whole of what step 4 changed and step 5 depends on -- and neither
# witness can produce the other's number: one is the adapter's record, the other
# is a hosted program's own observation of it.
if grep -qF "a Linux program execed: its own domain ended" "$LOG"; then
    kept=$(sed -n 's/.*linux exec *pid \([0-9]*\) kept across an exec: domain \([0-9]*\) became domain \([0-9]*\).*/\1 \2 \3/p' "$LOG" | tail -1)
    read -r pid from to <<<"$kept"
    if [[ -n $pid && -n $from && -n $to ]] && ((from != to)) && grep -qF "execed pid $pid" "$LOG"; then
        pass "a hosted program execed: pid $pid survived domain $from becoming domain $to, and the new program agrees"
    else
        fail "the exec did not keep its pid across the domain change: kept='${kept:-nothing}', console says '$(grep -aoE 'execed pid [0-9]+' "$LOG" | head -1)'"
        status=1
    fi
elif grep -qE "linux exec     skipped" "$LOG"; then
    pass "no second cpu, so the exec self-test was skipped"
else
    fail "the exec self-test did not conclude"
    status=1
fi

# RFC 0033 step 4: a pid is invented by the adapter and is **not** the domain
# id. The claim a coincidence cannot satisfy is the one gated here: two hosted
# programs that ran in the *same domain slot* were given **different** pids.
# Under the scheme this replaced -- `pid = domain + 1` -- they could not have
# been, because the number was a function of the slot, so arming it by putting
# that expression back turns `distinct` into `REUSED` and this red.
#
# Both halves are demanded: "distinct" alone would pass on a machine where no
# two programs ever shared a slot, which is a property of the boot rather than
# of the personality.
if grep -qE "linux pid .*distinct pids across [0-9]+ hosted programs, [1-9][0-9]* of which shared a domain slot" "$LOG"; then
    pass "a hosted pid is invented, not derived: a reused domain slot did not reuse a pid"
elif grep -qE "linux pid " "$LOG"; then
    fail "hosted pids: $(grep -aoE 'linux pid .*' "$LOG" | head -1)"
    status=1
else
    pass "no hosted program on this machine, so no pid was handed out"
fi

# And the exit check says so positively, not only by not failing. A line that
# stopped printing would take the whole instrument with it and nothing would
# notice -- which is how this project has lost a check before.
if grep -qF "none returned to ring 3 owning no space" "$LOG"; then
    pass "every exit to ring 3 owned an address space, and the check says so"
else
    fail "the boot did not say whether any exit to ring 3 owned no address space"
    status=1
fi

# The bill for the four fixed tables RFC 0033 step 3 raised, printed on every
# boot. Not gated on a size -- a threshold on static memory would be a gate on
# a linker's arithmetic -- but gated on being *said*: the numbers exist so that
# raising a limit is priced where a reviewer sees it, and a report line that
# quietly stopped printing would take that with it.
if grep -qE "fixed tables   spaces [0-9]+ x [0-9]+B, domains [0-9]+ x [0-9]+B, cspace [0-9]+ slots, arena [0-9]+ x [0-9]+B -- [0-9]+ KiB" "$LOG"; then
    pass "the fixed tables' cost is printed, not estimated"
else
    fail "the boot did not price its fixed tables"
    status=1
fi

# RFC 0015 step 5. A filesystem written, interrupted after the commit, and
# recovered by mounting it -- in the machine, on this target, with no std.
#
# The exhaustive proof is on the host, where the harness stops at every *device*
# write of every operation; what this adds is that the same code does the same
# thing here, on this target, with its pages in .bss. Four things in one line
# and all four matter: the cache answered reads without asking the device (a
# non-zero hit count, which is the whole of RFC 0015 step 6), the read-only
# mount *refused* an image with a pending transaction rather than quietly
# handing back the state before it, the replay wrote blocks, and the file the
# interrupted operation created is present -- it was acknowledged, so it must
# be.
if grep -qE "journal +wrote a filesystem through [0-9]+ cached pages \([1-9][0-9]* hits, [0-9]+ misses\), stopped it one device write after the commit, and mounting replayed [1-9][0-9]* blocks: .recovered. is there and so is .survivor." "$LOG"; then
    pass "a filesystem written, interrupted after its commit, and recovered by mounting"
else
    fail "the journal did not survive an interruption in the machine"
    grep -E "journal " "$LOG" || true
    status=1
fi

# RFC 0016 step 4 removed the kernel's own answer here. The kernel no longer
# names directories -- it does not know what an inode is -- so there is nothing
# for it to report. What replaced this gate is in the shell test, where the
# claims are made about what a *program* can and cannot reach, which is where
# they always belonged.


# RFC 0009 step 6: the filesystem service's bulk path, and the measurement the
# RFC asks for rather than a claim that it is faster. The register path stays
# for short transfers -- it is right for reading a filename and wrong for
# reading a file.
#
# The refusal is asserted with it: a caller naming a slot it does not hold is
# asking a service to write into memory it has no authority over, and a bulk
# path that skipped that check would be a faster way to read somebody else's
# memory.
# The multi-page count is asserted with them, and it is the one that matters
# for placement. A service in a domain copies through a buffer of its own, so
# "how much can it deliver" is a question the two placements can answer
# differently -- and did, silently, until 2026-08-11: the domain one returned
# one page and called that the file. `[1-9][0-9]{4,}` requires five figures,
# which is more than the 4096 that was being reported.
if grep -qE "bulk path +[0-9]+ bytes in 1 round trip against [0-9]+ by message; [1-9][0-9]{4,} bytes across pages, contents match, and a slot the caller does not hold is refused" "$LOG"; then
    pass "bulk data moves through shared memory, across pages, and only where the caller may write"
else
    fail "the bulk path did not move the file across pages, or did not refuse a slot the caller lacks"
    status=1
fi

# RFC 0011 step 6: an interrupt a domain holds, and the two refusals that make
# it mean something -- a legacy line may not be delegated at all (it is shared,
# and a holder that never acknowledges masks a line other devices need), and a
# notification capability is not authority over an interrupt however much of it
# a domain holds.
#
# "skipped" is a pass: the RFC will not take this step without an IOMMU, and
# `irq::name` enforces that rather than trusting anyone to remember it.
if grep -qE "irq grant +(a domain bound and acknowledged an interrupt it was given|skipped, no IOMMU)" "$LOG"; then
    pass "an interrupt is delegated only with the authority and the containment for it"
else
    fail "a domain took an interrupt it was not given, or delegation said nothing"
    status=1
fi

# RFC 0009 step 1: memory objects. The number in parentheses is the frame count
# before and after -- asserted as *equal* by the kernel, and printed so that a
# regression says by how much rather than only that there was one. This is the
# frame-leak gate pointed at the newest thing that can leak, which is the whole
# reason the object's frames are charged to an envelope at all.
# RFC 0005 step 9: a hosted Linux program uses a socket.
#
# **The four bytes are the gate, and the kernel line is not.** The probe gives
# up after a bounded retry and exits cleanly when no datagram returns, so "the
# domain ended" is true either way -- and the first version of this test said
# *passed* for a boot in which `bind` was refused, because `bhaskix-sock`
# requires the receiving slot to be declared before the call and the adapter
# was not doing it. Nothing failed loudly; the probe simply never received
# anything, and only looking for the payload found it.
#
# `dup0` is written into a page by the probe, sent to `[::1]`, and printed from
# what `recvfrom` gave back. It is in no file, no service and no part of the
# adapter, so it cannot appear unless the datagram made the round trip.
#
# Over v6 because `bin/ipd` reinjects loopback for v6 only. The v4 path is
# wired identically and is deliberately not claimed here.
if grep -qE "linux socket   a Linux program bound a UDP socket and sent a datagram" "$LOG"; then
    if grep -qF "dup0" "$LOG"; then
        pass "a hosted program bound a UDP socket and echoed a datagram to itself"
    else
        fail "the socket probe ran and no datagram came back -- bind, sendto or recvfrom is the \
one that did not work, and the adapter's own line will not tell you which"
        status=1
    fi
elif grep -qF "linux socket   skipped" "$LOG"; then
    pass "no network this machine can drive, so hosted sockets have nothing to ask"
else
    fail "the hosted socket test did not conclude: $(grep -aoE 'linux socket .*' "$LOG" | head -1)"
    status=1
fi

# RFC 0044's missing number, supplied.
#
# That RFC shipped un-measured -- and, worse, first claimed the boot report
# already priced this path when it did not. This gate is the correction: a lent
# page given back, timed by `bin/linuxd` where the cost is paid.
#
# **Two samples, and deliberately not called cold and warm.** The first reading
# was 7,877,036 cycles and then 10,049,460 -- the *second* larger -- so unlike
# `COPY_OUT` this path is not dominated by its first execution, and naming the
# second "warm" would assert a warming the numbers deny. What dominates is
# `bin/fsd`'s own mount and cache search inside the call.
#
# The number that actually prices what RFC 0044 added is on the `lending` line:
# the unmapping alone, best of eight, where a repeat is possible.
#
# And a warm figure exists at all only because of the change being measured:
# before it, a second hosted read on the machine was refused, so this path ran
# once per boot and had no steady state to report. The dark arm below says so
# when only one read happened, rather than passing quietly.
if grep -qE "lending cost   a lent page given back: [1-9][0-9]* cycles, then [1-9][0-9]*;" "$LOG"; then
    pass "giving a lent page back is priced, and says what dominates it"
elif grep -qF "lending cost" "$LOG"; then
    fail "only one hosted read on this boot, so the lending cost has no steady state: \
$(grep -aoE 'lending cost.*' "$LOG" | head -1)"
    status=1
elif grep -qF "linux file     skipped" "$LOG"; then
    pass "no filesystem service on this machine, so nothing is lent to price"
else
    fail "the lending cost was not reported at all"
    status=1
fi

# RFC 0044: a lending taken back from the borrower *alone*.
#
# The gate above revokes an object's **root** capability and checks both
# holders lost it. That operation was always right. This one is the operation
# every file read performs -- `bin/fsd` revokes the *lending* it derived from
# the capability naming its own cache frame -- and until 2026-08-23 it took the
# capability away and left the page mapped.
#
# Four properties in one line, and the point is that no plausible wrong fix
# gets all four. Unmapping every domain in the revocation tally passes "the
# borrower's page is gone" and fails "the lender kept both", because the lender
# is in that tally on every release. Routing through `shared::revoke_capability`
# passes the first and destroys the object. Clearing only the hardware entries
# passes both and fails "its address is free again", which is the half that put
# a hosted program's second file read out of reach.
if grep -qE "lending        a loan was taken back from the borrower alone: its page is gone and its address is free again, the lender kept both, and the object outlived the loan; the unmapping itself is [1-9][0-9]* cycles, best of 8" "$LOG"; then
    pass "revoking a lending unmaps the borrower, leaves the lender, frees the address -- and says what that cost"
else
    fail "the lending self test did not pass: $(grep -aoE 'lending .*' "$LOG" | head -1)"
    status=1
fi

if grep -qE "memory objects +[1-9][0-9]* created, [1-9][0-9]* destroyed, none live; two domains shared one object; [1-9][0-9]* mappings revoked out of their page tables; no frame lost" "$LOG"; then
    pass "two domains share an object, revocation takes it from both, nothing leaks"
else
    fail "the memory-object self test did not pass"
    status=1
fi

# The lock-order detector, checked *again* at the end of bring-up. The first
# check runs before the I/O APIC, the block driver's interrupt path, the memory
# objects and the services -- so on its own it verifies only the code that runs
# before it, and M6-07 shipped an inversion it could not have seen. A detector
# that looks once, early, is a detector with a blind spot the size of the rest
# of the boot.
if grep -qE "lock order +clean through bring-up too" "$LOG"; then
    pass "no lock-order violation anywhere in bring-up, not just before the check"
else
    fail "a lock-order violation appeared after the early check"
    status=1
fi

# The fast system-call path. Programmed values are read back from the MSRs
# rather than trusted, because every one of them is acted on without further
# checking and three decide what privilege level the machine returns to. The
# entry stub itself has no caller until ring 3 exists, and the kernel says so.
if grep -qE "syscall +entry armed on [1-9][0-9]* cpus" "$LOG"; then
    pass "SYSCALL entry armed and verified against the GDT"
else
    fail "syscall entry was not armed"
    status=1
fi

# Domains and the resource envelope. `docs/security.md` T10 says the envelope
# is enforced at allocation time, not by best effort, and §3 says a domain's
# CPU share holds regardless of how many threads it spawns — the second being
# the one a per-thread weight silently gets wrong.
if grep -qE "domains +[0-9]+ created; envelope refuses past its cap; shares divided" "$LOG"; then
    pass "domains: envelope enforced, CPU share independent of thread count"
else
    fail "domain self test did not pass"
    status=1
fi

# Synchronous IPC. The assertion is correctness, not throughput: every reply
# that arrived carried the value computed for *that* request, which catches a
# reply delivered to the wrong caller — possible precisely because two clients
# are in flight at once. Round counts vary by seventy times between runs on a
# loaded host, so a fixed count would measure the host.
# `0 wrong`, and not `N/N correct`. The back-reference compared two counters
# the machine had not sampled together: a client preempted between its own two
# increments printed `9/8` and the gate called a working machine broken, twice,
# and both times "load" was available as an explanation. The property is that
# no reply carried a wrong value, and that is one number.
if grep -qE "ipc +[0-9]+ rendezvous, [0-9]+ replies, [0-9]+ correct and 0 wrong; two badges distinguished" "$LOG"; then
    pass "synchronous IPC: rendezvous, correct replies, badges distinguish callers"
else
    fail "IPC self test did not pass"
    status=1
fi

# Ring 3. The evidence is *where* the kernel was entered from: a system call
# made by user code arrives with a return address inside the user program's
# page and a stack pointer inside the user stack, neither of which the kernel
# ever executes at or uses as a stack. Counting system calls alone would look
# identical to calling the dispatcher directly.
if grep -qE "ring 3 +[0-9]+ syscalls, [1-9][0-9]* interrupts from user mode; [1-9][0-9]* ipc calls badged 0x[0-9a-f]+; ring 3 derived, used and revoked its own capability \([1-9][0-9]* refused after\); loaded from bin/probe, three segments as its headers asked" "$LOG"; then
    pass "ring 3 runs a program loaded from disk, by capability, and revokes it"
else
    fail "ring 3 execution did not pass"
    status=1
fi

# RFC 0016 step 3, second half. The filesystem, in a domain, mounting a real
# disk through the block service -- and `bin/fsd` contains no filesystem code
# at all. It links `bhaskix-fs`, the same crate the kernel links, and supplies
# a `Store` made of system calls; that the crate needed nothing else is the
# return on RFC 0015 step 6, which gave it a trait instead of a slice.
#
# What is asserted is not that it mounted but that it read the *right bytes*:
# the kernel wrote a file into that filesystem through its own copy of the same
# crate, and the service found it. Two copies of one parser, one disk, and the
# same answer.
if true; then
    if grep -qE "fs domain +bin/fsd mounted the disk through the block service: [1-9][0-9]* sectors, [1-9][0-9]* blocks, [1-9][0-9]* entries, and .on-a-disk. reads [1-9][0-9]* bytes" "$LOG"; then
        pass "the filesystem, in a domain, read a real disk through the block service"
    elif grep -qE "fs domain +no block service on this machine" "$LOG"; then
        pass "no block service on this machine, so no disk for the filesystem to mount"
    else
        fail "the filesystem in a domain did not read the disk"
        grep -E "fs domain " "$LOG" || true
        status=1
    fi
fi

# RFC 0016 step 3, and the debt RFC 0015 step 1 left. Until `block::WRITE`
# existed the journal had only ever been exercised against an array in memory:
# correct, exhaustive, and silent about the one thing a journal is for. This is
# a filesystem on the virtio disk, written through the block service in another
# domain, stopped one device write *after* its commit, and recovered by
# mounting -- and what it reads back it reads off the disk, through a cache
# that has just been created and holds nothing.
#
# The exhaustive harness stays on the host, where stopping at every write of
# every operation costs milliseconds rather than a round trip each.
if grep -qE "disk journal +a filesystem on the virtio disk, through the block service: a create takes [1-9][0-9]* device writes to commit, the machine was stopped one write later, and mounting replayed [1-9][0-9]* blocks" "$LOG"; then
    pass "a journal on a real device survived being interrupted after its commit"
elif grep -qE "disk journal +no block service on this machine" "$LOG"; then
    pass "no block service on this machine, so no device to put a filesystem on"
else
    fail "the journal did not survive an interruption on a device"
    grep -E "disk journal " "$LOG" || true
    status=1
fi

# RFC 0016 step 2. A server that is not answering anybody has no caller, so it
# has nobody to hand a capability to. The driver asks before it starts serving
# and reports what it was told; the *other* refusal -- passing on a capability
# it may only hold -- has to be asked from inside a request or it is refused
# for having no caller instead, so the shell asks that one.
# Status 4 is `WrongObject`, and the number is asserted rather than "refused":
# the driver declares a receive slot before it asks, so the reply obligation is
# the only rule left that can refuse it. Without the declaration it would be
# refused for not having said where -- which is what an earlier version of this
# gate accepted, and it accepted it with the rule deleted.
#
# RFC 0022 changed what the right answer is: a hand while answering nobody now
# *stages* the capability for the thread's next call. The property watched is
# therefore the new mechanism's promise -- the hand is accepted AND the slot
# the driver had declared stayed empty, because a staged gift moves only at a
# rendezvous the stager initiates. A capability landing without a call would
# be the old bug wearing the new rule, and fails here.
if grep -qE "a hand while answering nobody staged and installed nothing \(pair 0x2\)" "$LOG"; then
    pass "a hand outside a reply stages, and installs nothing until a rendezvous"
elif grep -qE "block domain +no second device" "$LOG"; then
    pass "no block domain on this machine, so nothing to hand anything"
else
    fail "a hand outside a reply did not behave as RFC 0022 specifies"
    status=1
fi

# RFC 0022 step 2. The whole transfer, exercised by the kernel's own
# self-test with a domained service and a domained client: a capability
# crossed at a rendezvous and landed in the slot the service had declared and
# nowhere else; the staged gift was consumed by the call that carried it; a
# call with no gift was untouched by the machinery; a gift the client lacked
# GRANT for refused the *call* -- the message was never delivered, the caller
# saw `InsufficientRights` -- and the service's declaration was restored, so
# the very next gift landed in it without a second declaration.
#
# The line is matched on its tail because the interesting clause is the last
# one: restoration is the part a simpler implementation silently gets wrong,
# by consuming the declaration on the failure path and leaving the service
# one failed caller away from deafness.
if grep -qE "gift .*unmapped, destroyed and unnamed what it had lent" "$LOG"; then
    pass "a capability crossed in a call; a refusal restored; a lender's death revoked"
elif grep -qE "gift +skipped" "$LOG"; then
    pass "gift self-test skipped on this machine, too few cpus"
else
    fail "the gift self-test did not report RFC 0022 step 2's properties"
    status=1
fi

# The hold-leak canary must never fire. A nonzero kernel hold count at a
# return to ring 3 vetoes preemption on that CPU until it returns to zero,
# which nothing will then do -- it is the captured boot hang, and the canary
# names the leaking system call the moment it happens instead of forty-five
# seconds later.
if grep -q "HOLD LEAK" "$LOG"; then
    fail "a system call returned to ring 3 holding a kernel lock count"
    grep -E "HOLD LEAK|hold leaks" "$LOG" | head -3
    status=1
fi

# The hold-count underflow, caught at release, and its upstream shadow --
# the mask-held/count-zero mismatch. Both used to wedge a CPU silently
# (2026-08-17: three bring-up hangs, two silent-CPU boots, one count at
# 4294967295); the saturating release now lets such a boot finish and
# report, so the gate is what turns the survivable report back into a
# failure nobody can miss.
if grep -qa "COUNT UNDERFLOW" "$LOG"; then
    fail "a hold-count underflow was caught at a release"
    status=1
fi
if grep -qa "COUNT MISMATCH" "$LOG"; then
    fail "a CPU's rank mask and hold count disagreed"
    status=1
fi

# The lock-contention gauge must exist on every boot, same rule as every
# instrument: values ungated, presence demanded.
if ! grep -qE "longest holds" "$LOG"; then
    fail "the longest-holds gauge is missing"
    status=1
fi

# The scheduler's wake-to-dispatch measurement must exist on every boot:
# wakes happen on all of them, and an instrument that vanishes is a
# regression even when nothing gates its values.
#
# **And the worst case must name its thread**, which is asserted here because
# the number alone misled for a day. Every boot reports a worst of about 8.027
# seconds; it is thread `boot` waiting through bring-up while the self-tests run
# on the same CPU, not a scheduling stall. A worst case that is the same
# constant on every run is measuring something other than what it claims, and
# the name is what lets a reader tell the two apart — so the name is gated, not
# merely printed.
if grep -qE "wake to run +[0-9]+ wakes; p50 [0-9]+ us, p99 [0-9]+ us, mean [0-9]+ us; worst [0-9]+ us was thread [0-9]+ \([a-z0-9_-]+\)" "$LOG"; then
    pass "wake-to-dispatch is measured, and its worst case names the thread it happened to"
else
    fail "the wake-to-dispatch measurement is missing"
    status=1
fi

# RFC 0016 step 1. A badge says who the *granter* said a caller is. Until this
# was fixed a holder could derive itself a different one and call a service as
# somebody else, and the probe below demonstrated it as though it were a
# feature.
#
# Both halves are asserted, and neither is worth anything alone: the probe
# delegates its capability under the same badge and the call arrives, *and* it
# asks for one under a badge it invented and is refused. A kernel that refused
# every derivation would pass the second on its own.
if grep -qE "ring 3 +[0-9]+ syscalls.*ring 3 derived, used and revoked its own capability" "$LOG"; then
    pass "ring 3 delegated a capability, and could not rename itself doing it"
else
    fail "the badge rule did not hold from ring 3"
    grep -E "ring 3 " "$LOG" || true
    status=1
fi

# Capabilities: the load-bearing security mechanism. The rules are proved
# exhaustively on the host; this asserts they hold against the real global
# arena, through its lock, and that nothing leaked.
if grep -qF "derive is monotone in rights and in badges, revoke is transitive and immediate" "$LOG"; then
    pass "capabilities: monotone derivation in rights and badges, immediate transitive revocation"
else
    fail "capability self test did not pass"
    status=1
fi

# The fault path's per-CPU frame reserve. Held frames prove it is populated;
# the "fault serviced while the allocator lock was held" property is gated by
# the demand-paging assertion above, which only prints its success line when
# every one of its checks passed.
if grep -qE "frame reserve +[1-9][0-9]* frames held across [0-9]+ cpus" "$LOG"; then
    pass "per-CPU frame reserve populated for the fault path"
else
    fail "frame reserve is empty or absent"
    status=1
fi

# Lock ordering. Three claims in one line, and only the last is the one people
# quote: that acquisitions were actually *checked* (zero violations is what a
# checker that never ran also reports), that the detector fires when given a
# deliberate inversion, and that the real count is zero.
if grep -qE "lock order +[1-9][0-9]* acquisitions checked, detector verified, 0 violations" "$LOG"; then
    pass "lock ordering declared and enforced, no violations"
else
    fail "lock ordering check did not pass"
    status=1
fi

# Balancing. The previous assertion requires threads to stay where they were
# created; this one requires them to move. They are not in tension: the first
# runs with one thread per CPU, where there is no imbalance to correct, and
# this one deliberately creates every thread on CPU 0. A kernel that pinned
# threads forever would pass the first and fail this; a kernel that scattered
# them at random would pass this and fail the first.
if grep -qE "migration +[0-9]+ threads stolen; [1-9][0-9]* of [0-9]+ ran off their creating cpu" "$LOG"; then
    pass "idle CPUs steal work from a loaded one"
else
    fail "work stealing did not move any thread"
    status=1
fi

# **The report stopped printing the slide on 2026-08-23** (RFC 0042: it is the
# one secret in a report that is about to be readable from ring 3), so this
# accepts either wording. What it asserts is unchanged and is all it ever
# asserted: that KASLR *happened*. The number itself is checked on the native
# lane, which asks for it with `kaslr=show` and compares it against the slide the
# loader drew -- a stronger check, and the one that needs the value.
if grep -qE "kaslr +(applied and confirmed|slid 0x[0-9a-f]+ bytes)" "$LOG" \
   && ! grep -qF "kaslr           NOT APPLIED" "$LOG"; then
    pass "KASLR applied (kernel image slid from its link-time base)"
else
    fail "KASLR was not applied -- the kernel is at its link-time base"
    status=1
fi

# Conditioned on the machine's own feature report, because this script boots
# two machines: `-cpu max` has SMEP and SMAP and must have enabled them, and
# CI's `-cpu qemu64` has neither and must say so with dashes rather than
# claiming protection it does not have. Either machine printing the other's
# line is the failure.
if grep -qE "features .*smep yes" "$LOG"; then
    if grep -qE "supervisor +smep on +smap on" "$LOG"; then
        pass "SMEP and SMAP enabled"
    else
        fail "the machine has SMEP/SMAP and they were not enabled"
        status=1
    fi
elif grep -qE "features .*smep +NO" "$LOG"; then
    if grep -qE "supervisor +smep -- +smap --" "$LOG"; then
        pass "no SMEP/SMAP on this machine, and the report says so honestly"
    else
        fail "a machine without SMEP/SMAP claimed something else"
        status=1
    fi
else
    fail "the features line never said whether SMEP exists"
    status=1
fi

if grep -qE "exception-table (entry|entries)" "$LOG" \
   && ! grep -qF "(0 exception-table" "$LOG"; then
    pass "exception table populated (bad user pointers fault, not panic)"
else
    fail "the exception table is empty -- a bad user pointer would panic"
    status=1
fi

# RFC 0021: the machine can be unpredictable, and proved it rather than
# reporting a feature bit.
#
# A positive gate as well as the `FAILED` marker, for the reason the marker list
# gives: `FAILED` catches a self-test that ran and failed, and only a positive
# assertion catches one that stopped running at all. This one is easy to lose --
# it lives inside a feature report that would go on printing perfectly well
# without it.
#
# Conditioned on the machine's own `rdrand` report, because this script boots
# two machines and each owes a different sentence. `-cpu max` has RDRAND and
# must demonstrate it -- two draws that differ. CI's `-cpu qemu64` has none
# and must print RFC 0021's honest refusal instead, which is the policy the
# RFC's acceptance watched working on exactly that machine. A comment here
# used to say a machine without RDRAND "is a different machine from the one
# this gate is about" -- written as if the harness only ever booted `-cpu
# max`, while CI had been booting qemu64 through this same script since the
# APIC matrix existed. Both machines are this gate's business now, and a
# bright machine printing the dark line fails just as a dark one printing
# nothing does.
if grep -qE "rdrand yes" "$LOG"; then
    if grep -qF "unpredictable  two draws differ" "$LOG"; then
        pass "the machine can produce an unpredictable number, demonstrated not declared"
    else
        fail "no source of unpredictability was demonstrated -- RFC 0021, and TCP depends on it"
        status=1
    fi
elif grep -qE "rdrand +NO" "$LOG"; then
    if grep -qF "unpredictable  NO: this machine has no source of randomness" "$LOG"; then
        pass "no unpredictability on this machine, refused honestly rather than guessed"
    else
        fail "a machine without RDRAND neither demonstrated nor refused -- RFC 0021's policy is absent"
        status=1
    fi
else
    fail "the features line never said whether RDRAND exists"
    status=1
fi

# The handoff must have been validated, not skipped.
if grep -qF "handoff version 2" "$LOG"; then
    pass "handoff accepted"
else
    fail "handoff was not reported -- validation may have been skipped"
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo
    echo "--- captured serial output ---"
    cat "$LOG"
    echo "--- end ---"
fi

exit $status
