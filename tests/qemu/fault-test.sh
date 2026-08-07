#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M2 exit criterion, as an executable check.
#
# For each injectable fault: build an image that triggers it, boot it, and
# assert that the kernel produced the right diagnostic and halted — rather than
# triple-faulting, rebooting, or silently swallowing the exception.
#
# This is the test that decides whether M2 is done. Everything else in M2 is
# machinery in service of it.
#
#   tests/qemu/fault-test.sh          # all faults
#   tests/qemu/fault-test.sh pf df    # only these

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

TIMEOUT="${FAULT_TEST_TIMEOUT:-120}"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; DIM=$'\033[2m'; RESET=$'\033[0m'

# fault : expected substrings, one per line, ALL of which must appear.
#
# Each expectation is chosen to prove something specific, not just that output
# happened:
#   - the vector was decoded to a name  (the IDT gate points at the right stub)
#   - the mode was identified           (CS was read, not assumed)
#   - fault-specific detail appeared    (the error-code decoder ran)
declare -A EXPECT=(
  [de]='EXCEPTION: divide error (#DE)
from kernel mode
rip '
  [ud]='EXCEPTION: invalid opcode (#UD)
from kernel mode
rip '
  [bp]='EXCEPTION: breakpoint (#BP)
from kernel mode'
  [gp]='EXCEPTION: general protection fault (#GP)
error code
selector index'
  [pf]='EXCEPTION: page fault (#PF)
faulting address
page not present
while writing'
  [df]='EXCEPTION: double fault (#DF)
kernel stack overflow
guard page
own IST stack'
  # The odd one out, and the only one whose point is what happens *next*.
  #
  # The first six are kernel faults and every one of them ends the machine, so
  # their expectations stop at "the report was right". This one is a fault in a
  # program: it must end that domain and nothing else. A report proves nothing
  # on its own -- before RFC 0017 step 1 the report was already correct, and
  # then the CPU halted forever with the domain still live and its memory still
  # charged.
  #
  # So the last two lines are the assertion. `user fault` only prints if the
  # domain went away and the table took its slot back, and the milestone banner
  # only prints if the boot ran to completion *after* a ring 3 fault.
  [user]='EXCEPTION: page fault (#PF)
from USER mode
this is a null pointer dereference
Domain "faulter" is gone
a ring 3 fault ended its domain and nothing else
Nothing left to do at this milestone'
)

FAULTS=("$@")
[[ ${#FAULTS[@]} -eq 0 ]] && FAULTS=(de ud bp gp pf df user)

# Anything here means the machine did not survive to report cleanly.
FATAL_MARKERS=(
  "FAULT INJECTION RETURNED"   # exception swallowed, execution continued
)

status=0


# Runs QEMU until `marker` appears in the log, or the timeout expires.
#
# The kernel halts rather than exiting, so waiting for QEMU to finish means
# waiting the entire timeout on *every* run, pass or fail. That coupling is
# what made the timeout impossible to tune: long enough to survive a loaded
# build machine also meant minutes of dead waiting per case. Polling separates
# the two -- a healthy boot finishes in seconds and the timeout goes back to
# being an upper bound rather than the running cost.
# Returns *why* it stopped, which the caller reports:
#
#   0  every expected line appeared
#   1  the deadline passed and they had not
#   2  qemu exited before they did
#
# The distinction is the whole reason this returns anything. Before it did, a
# machine that was still booting when the clock ran out was reported as
# "missing: 'EXCEPTION: divide error'" -- which reads as a kernel that
# mishandled a fault, and sent one investigation down entirely the wrong path.
# A timeout on a loaded host and a broken exception handler are not the same
# failure and must not print the same way.
run_until() {
    local logfile="$1" expected="$2" limit="$3"; shift 3
    : > "$logfile"
    timeout "$limit" qemu-system-x86_64 "$@" >/dev/null 2>&1 &
    local pid=$! waited=0 outcome=1
    while kill -0 "$pid" 2>/dev/null; do
        # Every expected line, not just the first. The exception report is
        # written a line at a time, so stopping the machine once the header
        # appears loses the register dump -- which is most of what is being
        # asserted, and failed exactly that way on a loaded host.
        local complete=1 line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            grep -qF -- "$line" "$logfile" 2>/dev/null || { complete=0; break; }
        done <<< "$expected"
        [[ $complete -eq 1 ]] && { outcome=0; break; }

        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((limit * 4)) ]] && break
    done

    # The machine may have printed everything and exited between two polls, so
    # the log is checked once more before the process's death is called a
    # failure.
    if [[ $outcome -ne 0 ]]; then
        local line complete=1
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            grep -qF -- "$line" "$logfile" 2>/dev/null || { complete=0; break; }
        done <<< "$expected"
        [[ $complete -eq 1 ]] && outcome=0
    fi

    # Who ended the machine decides which failure this is, and the previous
    # version could not tell: it called any dead process "qemu exited early",
    # but `timeout` kills qemu at exactly the deadline, so a plain timeout was
    # *always* reported as an early exit. Every slow boot arrived labelled as a
    # missing image or disk. `timeout` reports 124 when the deadline is what
    # killed it, which is the distinction, taken from the process rather than
    # inferred from the clock.
    local killed_by_us=0
    if kill -0 "$pid" 2>/dev/null; then
        killed_by_us=1
        kill "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
    local qemu_status=$?

    if [[ $outcome -ne 0 ]]; then
        if [[ $killed_by_us -eq 1 || $qemu_status -eq 124 ]]; then
            outcome=1
        else
            outcome=2
        fi
    fi
    return $outcome
}

for fault in "${FAULTS[@]}"; do
  if [[ -z "${EXPECT[$fault]+set}" ]]; then
    echo "${RED}FAIL${RESET}  unknown fault '$fault'"
    status=1
    continue
  fi

  printf '%-4s ' "$fault"

  if ! make iso CMDLINE="bhaskix.fault=$fault" >/dev/null 2>&1; then
    echo "${RED}FAIL${RESET}  could not build image"
    status=1
    continue
  fi

  log="$(mktemp)"
  qemu_log="$(mktemp)"
  run_until "$log" "${EXPECT[$fault]}" "$TIMEOUT" \
      -M q35 -cpu ${QEMU_CPU:-max} -m 256M -no-reboot -cdrom build/bhaskix.iso -boot d \
      -drive file=build/initrd.tar,format=raw,if=none,id=disk0,readonly=on \
      -device virtio-blk-pci,drive=disk0 \
      -serial "file:$log" -display none \
      -d cpu_reset -D "$qemu_log"
  verdict=$?

  failures=()

  # Lead with why the run ended, when it did not end well. Everything below
  # this describes *what was in the log*, which is only meaningful once the
  # machine got far enough to write it.
  case $verdict in
    1) failures+=("timed out after ${TIMEOUT}s -- not all of the expected output appeared. On a loaded host that is often a slow boot; the missing lines below say which part is absent, and for a survivable fault the difference between 'the report never came' and 'everything after it never came' is the whole diagnosis") ;;
    2) failures+=("qemu exited before the fault was reported -- check that the image and the disk were both available") ;;
  esac

  # The decisive check: a triple fault resets the CPU, and QEMU logs it.
  # This is the difference between "reported the fault" and "died".
  if grep -qi 'triple fault' "$qemu_log"; then
    failures+=("machine TRIPLE FAULTED instead of reporting")
  fi

  # Always, not only on a clean verdict. Which expectation is missing is the
  # most useful thing this test knows, and withholding it on a timeout meant
  # two entirely different breakages -- a machine that halted, and one that ran
  # perfectly but never reported a domain gone -- printed the same sentence.
  while IFS= read -r expected; do
    [[ -z "$expected" ]] && continue
    grep -qF -- "$expected" "$log" || failures+=("missing: '$expected'")
  done <<< "${EXPECT[$fault]}"

  for marker in "${FATAL_MARKERS[@]}"; do
    grep -qF -- "$marker" "$log" && failures+=("$marker")
  done

  if [[ ${#failures[@]} -eq 0 ]]; then
    # Show the headline the kernel printed, so a passing run is still
    # informative rather than a wall of green.
    headline=$(grep -m1 -E 'EXCEPTION:|UNEXPECTED INTERRUPT' "$log" | sed 's/^ *//')
    echo "${GREEN}ok${RESET}    ${DIM}${headline}${RESET}"
  else
    echo "${RED}FAIL${RESET}"
    for failure in "${failures[@]}"; do
      echo "        $failure"
    done
    echo "      ${DIM}--- serial ---${RESET}"
    sed 's/^/      /' "$log" | head -40
    echo "      ${DIM}--- end ---${RESET}"
    status=1
  fi

  rm -f "$log" "$qemu_log"
done

# Leave a normal image behind, so a failed run does not silently poison the
# next `make run` with a fault-injecting build.
make iso >/dev/null 2>&1

if [[ $status -eq 0 ]]; then
  echo "${GREEN}ok${RESET}    every injected fault was reported, none triple-faulted"
fi

exit $status
