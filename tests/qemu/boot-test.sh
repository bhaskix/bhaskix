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
LOG="$(mktemp)"
TIMEOUT="${BOOT_TEST_TIMEOUT:-120}"

trap 'rm -f "$LOG"' EXIT

# The greeting is the milestone's contract. If you reword it, update
# docs/roadmap.md M1 and kernel/src/lib.rs::banner in the same change.
EXPECT_GREETING="Hello from Bhaskix"

# Strings that mean the boot went wrong even if the greeting appeared.
FAILURE_MARKERS=("KERNEL PANIC" "FATAL:" "WARNING: the memory map was truncated"
                 "unexpected interrupt on vector" "NO TICKS"
                 "LEAK:" "INVARIANT VIOLATED")
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

MACHINE="q35"
IOMMU_ARGS=()
VIRTIO_ARGS=(-device virtio-blk-pci,drive=disk0)
if [[ "$MODE" == "iommu" ]]; then
    # RFC 0012's testing plan turns on what the RFC is about. `intremap=on`
    # needs a split irqchip, and both are QEMU's requirements rather than this
    # kernel's -- nothing here programs the unit yet, so what is under test is
    # discovery: that the `DMAR` the firmware writes is found, parsed, and
    # described, on a machine that has one.
    MACHINE="q35,kernel-irqchip=split"
    IOMMU_ARGS=(-device intel-iommu,intremap=on)
    # And the device must actually be *subject* to it. A virtio device without
    # `iommu_platform` bypasses translation entirely on QEMU, so every
    # assertion below would pass on a machine where the IOMMU protects
    # nothing -- which is exactly what the first version of this did.
    VIRTIO_ARGS=(-device virtio-blk-pci,drive=disk0,disable-legacy=on,iommu_platform=on)
fi

QEMU_ARGS=(-M "$MACHINE" -cpu ${QEMU_CPU:-max} -smp "${QEMU_SMP:-4}" -m 256M -no-reboot -cdrom "$ISO" -boot d
           -drive "file=$DISK,format=raw,if=none,id=disk0,readonly=on"
           "${VIRTIO_ARGS[@]}"
           "${IOMMU_ARGS[@]}"
           -serial "file:$LOG" -display none)

if [[ "$MODE" == "uefi" ]]; then
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

echo "booting ($MODE), up to ${TIMEOUT}s..."
run_until "$LOG" "Nothing left to do at this milestone" "$TIMEOUT" "${QEMU_ARGS[@]}"

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

# Shootdown reaching nobody looks exactly like shootdown working, so the
# acknowledgement count is what gets checked. Negative-tested by disabling the
# receiving handler, which turns 8 completions into 8 timeouts.
if grep -qE "tlb shootdown +[0-9]+ completed across [0-9]+ cpus, none timed out" "$LOG"; then
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
if grep -qE "vfs +[0-9]+ entries in /, 2 in /bin; bin/probe is ELF64, entry 0x10000000, 3 segments" "$LOG"; then
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
if grep -qE "services +[0-9]+ entries listed, [0-9]+ bytes read by message; [0-9]+ requests, [1-9][0-9]* callers refused" "$LOG"; then
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

# RFC 0012 step 1, and only on the machine that has one: the units the firmware
# describes are found and described. "not enabled" is asserted with them --
# nothing is programmed at this step, and a line that claimed an IOMMU without
# saying so would read as protection the machine does not have.
if [[ "$MODE" == "iommu" ]]; then
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
    if grep -qE "iommu window +[0-9a-f]{2}:[0-9a-f]{2}\.[0-9] [0-9]+-bit, [0-9]+ levels" "$LOG"; then
        pass "the device's translation structures are built and verified"
    else
        fail "the IOMMU window was not built, or did not read back as written"
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
    if grep -qE "iommu memory +an object was reachable at 0x[0-9a-f]+.*revoked, and the device was then refused it" "$LOG"; then
        pass "a revoked object is taken away from the device, not just from the page tables"
    else
        fail "a device kept reaching a revoked object, or the refusal was not reported"
        status=1
    fi

    # RFC 0012 step 6 is built and **off**, and the machine says so. The
    # assertion is that it states which world it is in, not that remapping is
    # on: under remapping the I/O APIC's line is delivered and the block
    # device's message is not, so enabling it by default would cost that driver
    # its interrupt and leave it polling behind a timer. A machine that quietly
    # degraded would pass every other gate here.
    if grep -qE "iommu irq +(interrupts NOT remapped|remapping interrupts;)" "$LOG"; then
        pass "the machine says whether a device can still forge an interrupt"
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

# RFC 0009 step 6: the filesystem service's bulk path, and the measurement the
# RFC asks for rather than a claim that it is faster. The register path stays
# for short transfers -- it is right for reading a filename and wrong for
# reading a file.
#
# The refusal is asserted with it: a caller naming a slot it does not hold is
# asking a service to write into memory it has no authority over, and a bulk
# path that skipped that check would be a faster way to read somebody else's
# memory.
if grep -qE "bulk path +[0-9]+ bytes in 1 round trip against [0-9]+ by message; contents match, and a slot the caller does not hold is refused" "$LOG"; then
    pass "bulk data moves through shared memory, and only where the caller may write"
else
    fail "the bulk path did not move the file, or did not refuse a slot the caller lacks"
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
if grep -qE "ipc +[0-9]+ rendezvous, [0-9]+ replies, ([0-9]+)/\1 correct; two badges distinguished" "$LOG"; then
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
if grep -qE "ring 3 +[0-9]+ syscalls, [1-9][0-9]* interrupts from user mode; [1-9] ipc calls badged 0x[0-9a-f]+; ring 3 derived, used and revoked its own capability \([1-9][0-9]* refused after\); loaded from bin/probe, three segments as its headers asked" "$LOG"; then
    pass "ring 3 runs a program loaded from disk, by capability, and revokes it"
else
    fail "ring 3 execution did not pass"
    status=1
fi

# Capabilities: the load-bearing security mechanism. The rules are proved
# exhaustively on the host; this asserts they hold against the real global
# arena, through its lock, and that nothing leaked.
if grep -qF "derive is monotone, revoke is transitive and immediate" "$LOG"; then
    pass "capabilities: monotone derivation, immediate transitive revocation"
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

if grep -qE "supervisor +smep on +smap on" "$LOG"; then
    pass "SMEP and SMAP enabled"
else
    fail "SMEP/SMAP not enabled"
    status=1
fi

if grep -qE "exception-table (entry|entries)" "$LOG" \
   && ! grep -qF "(0 exception-table" "$LOG"; then
    pass "exception table populated (bad user pointers fault, not panic)"
else
    fail "the exception table is empty -- a bad user pointer would panic"
    status=1
fi

# The handoff must have been validated, not skipped.
if grep -qF "handoff version 1" "$LOG"; then
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
