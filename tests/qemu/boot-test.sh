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
run_until() {
    local logfile="$1" marker="$2" limit="$3"; shift 3
    : > "$logfile"
    timeout "$limit" qemu-system-x86_64 "$@" >/dev/null 2>&1 &
    local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if grep -qF -- "$marker" "$logfile" 2>/dev/null; then
            # Let the last few lines land before stopping the machine.
            sleep 1
            break
        fi
        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((limit * 4)) ]] && break
    done
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
    QEMU_ARGS+=(-drive "format=raw,file=fat:rw:$ESP")
fi

# The domain's disk is written to now, so it is rebuilt before every run.
# A fixture a test mutates is a fixture whose next run starts somewhere nobody
# chose, and this one carries the marker other checks look for in sector zero.
rm -f "$REPO_ROOT/build/domain-disk.img"
make -C "$REPO_ROOT" build/domain-disk.img >/dev/null 2>&1 || true

# RFC 0020 step 5's inbound driver: a host-side client that connects *into*
# the guest through hostfwd, sends sixteen bytes, and demands them back.
# Retried for the whole boot, because the guest's listener arms only after
# its outbound demonstration completes; each attempt is cheap and the loop
# dies with the boot. `/dev/tcp` is bash itself, so the harness needs no new
# tool. The verdict lands in a file, because the driver is a background job
# and its exit status would be lost. On a machine with no network the
# connection is never accepted, the file stays absent, and the gate's dark
# arm expects exactly that.
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

echo "booting ($MODE), up to ${TIMEOUT}s..."
run_until "$LOG" "Nothing left to do at this milestone" "$TIMEOUT" "${QEMU_ARGS[@]}"
kill "$INBOUND_DRIVER" 2>/dev/null || true
wait "$INBOUND_DRIVER" 2>/dev/null || true

status=0

# If the machine never finished booting, every assertion below fails for one
# reason and prints thirty of them. That wall of red says nothing about which
# thing broke, and it has twice been mistaken for a catastrophic regression
# when the actual cause was a second QEMU holding the disk image or a loaded
# host. One accurate line is worth more than thirty misleading ones.
if ! grep -qF "Nothing left to do at this milestone" "$LOG"; then
    fail "the machine did not finish booting within ${TIMEOUT}s"
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

# Spawn-to-first-dispatch, bounded. Unlike the 50 us wakeup target above, this
# one IS asserted, with three orders of magnitude of headroom on either side:
# with spawn requesting a reschedule it measures under a millisecond, and
# without one it measured 446-500 *milliseconds* -- a priority-90 thread
# waiting behind a spinning fair thread on a CPU whose timer had gone tickless
# because it was busy but alone. The bound is 50 ms so no emulator slowness
# can trip it, and no return of the hole can pass it.
spawn_us=$(grep -aoE "spawn to first run [0-9]+ us" "$LOG" | grep -oE "[0-9]+" || echo "")
if [[ -n "$spawn_us" && "$spawn_us" -lt 50000 ]]; then
    pass "a spawned thread reaches its first dispatch promptly ($spawn_us us)"
else
    fail "spawn to first dispatch took ${spawn_us:-unmeasured} us -- the tickless spawn hole is back"
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
if grep -qE "vfs +[0-9]+ entries in /, 13 in /bin; bin/probe is ELF64, entry 0x10000000, 3 segments" "$LOG"; then
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
    if grep -qE "iommu +[1-9][0-9]* unit(s)? found, not enabled; [0-9]+-bit addresses" "$LOG"; then
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
# describes are found and described. "not enabled" is asserted with them --
# nothing is programmed at this step, and a line that claimed an IOMMU without
# saying so would read as protection the machine does not have.
if [[ "$MODE" == "iommu" || "$MODE" == "fsd" ]]; then
    if grep -qE "iommu +[1-9][0-9]* unit(s)? found, not enabled; [0-9]+-bit addresses" "$LOG"; then
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
if grep -qE "tcp client +echoed outbound" "$LOG" && ! grep -qE "tcp measure +handshake [0-9]+ us" "$LOG"; then
    fail "the networked boot produced no TCP measurement"
    status=1
fi

if grep -qE "tcp client +echoed outbound through rings it owns, then listened, accepted" "$LOG"; then
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
domains=$(grep -o "=domain" <<<"$expected" | wc -l)
want=$((1 + domains))
spaces=$(sed -n 's/.*address spaces \([0-9]*\) in use at once.*/\1/p' "$LOG" | tail -1)
if [[ -n $spaces ]] && ((spaces >= want)); then
    pass "each user program has an address space of its own ($spaces, wanted $want)"
else
    fail "wanted at least $want address spaces in use, found ${spaces:-none}"
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
if grep -qE "wake to run +[0-9]+ wakes; p50 [0-9]+ us, p99 [0-9]+ us" "$LOG"; then
    pass "wake-to-dispatch is measured, not guessed"
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

if grep -qE "kaslr +slid 0x[0-9a-f]+ bytes" "$LOG" \
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
