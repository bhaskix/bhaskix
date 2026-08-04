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
)

FAULTS=("$@")
[[ ${#FAULTS[@]} -eq 0 ]] && FAULTS=(de ud bp gp pf df)

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
run_until() {
    local logfile="$1" expected="$2" limit="$3"; shift 3
    : > "$logfile"
    timeout "$limit" qemu-system-x86_64 "$@" >/dev/null 2>&1 &
    local pid=$! waited=0
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
        [[ $complete -eq 1 ]] && break

        sleep 0.25
        waited=$((waited + 1))
        [[ $waited -gt $((limit * 4)) ]] && break
    done
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 0
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
      -drive file=build/initrd.tar,format=raw,if=none,id=disk0 \
      -device virtio-blk-pci,drive=disk0 \
      -serial "file:$log" -display none \
      -d cpu_reset -D "$qemu_log"

  failures=()

  # The decisive check: a triple fault resets the CPU, and QEMU logs it.
  # This is the difference between "reported the fault" and "died".
  if grep -qi 'triple fault' "$qemu_log"; then
    failures+=("machine TRIPLE FAULTED instead of reporting")
  fi

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
