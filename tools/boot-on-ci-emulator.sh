#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the boot lanes on **the emulator CI actually uses**, not the one this
# machine happens to have.
#
# Usage:  tools/boot-on-ci-emulator.sh [lane] [count]   # default: all four, once
#         tools/boot-on-ci-emulator.sh bios 6
#
# # Why this exists
#
# `TRACKER.md` said, repeatedly and correctly, that **the boot lanes had never
# been run on the emulator CI uses**. This machine has QEMU 4.2.1; the runner
# installs `qemu-system-x86` from Ubuntu 24.04, which is 8.2.2 -- four major
# versions apart. So when two boot lanes went red on docs-only commits in August
# 2026 and would not reproduce locally, "it passes here" was carrying weight it
# had not earned: it established that the gates pass on 4.2.1 and said very
# little about a failure on 8.2.2.
#
# That gap was a *belief about what was possible*, not a limit. A container with
# the runner's base image has the runner's emulator, and the harness does not
# care what is underneath it. First run, 2026-08-25: all four matrix cells --
# `bios`/`uefi` crossed with `-cpu max`/`-cpu qemu64` -- **24 boots, 24 passes,
# 109 gates each**, on 8.2.2.
#
# **What that result is and is not.** It discharges the limit: the lanes have
# now run on CI's emulator. It does *not* explain runs 328 and 330, and does not
# disprove a version-specific cause -- those were roughly two failures in
# fifteen pushes, and twenty-four clean runs is evidence against a determinism,
# not against a rare race. What it removes is the excuse for never having looked.
#
# # What it deliberately is not
#
# Not part of `make test`, and not a gate. It needs a network, a Docker daemon
# and a few hundred megabytes of image; a check that needs all three is not
# something every build should depend on, for the same reason `ci-status.sh` is
# not in `make gates`. This is a thing a person runs when a lane goes red on CI
# and not here.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${BHASKIX_CI_EMU_IMAGE:-bhaskix-qemu822}"
# Matches `runs-on: ubuntu-latest` at the time of writing. Pinned as a variable
# rather than buried, because the day the runner moves this is the line that has
# to move with it -- and a tool that silently tests the wrong emulator is worse
# than one that does not exist.
BASE="${BHASKIX_CI_EMU_BASE:-ubuntu:24.04}"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; DIM=$'\033[2m'; RESET=$'\033[0m'

command -v docker >/dev/null 2>&1 || {
    echo "${YELLOW}ci-emulator${RESET}  needs docker -- this says nothing about the lanes" >&2
    exit 3
}
docker info >/dev/null 2>&1 || {
    echo "${YELLOW}ci-emulator${RESET}  the docker daemon is not reachable -- this says nothing about the lanes" >&2
    exit 3
}

LANE="${1:-all}"
COUNT="${2:-1}"

# Built once and reused. `docker build` is a no-op when the layers are cached,
# so this costs nothing after the first run and cannot silently use a stale
# image built from a different base.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "${DIM}  building $IMAGE from $BASE (first run only)...${RESET}"
    docker build -q -t "$IMAGE" - >/dev/null <<EOF || {
FROM $BASE
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      qemu-system-x86 xorriso mtools ovmf make python3 \
 && rm -rf /var/lib/apt/lists/*
EOF
        echo "${RED}ci-emulator${RESET}  could not build the image" >&2
        exit 3
    }
fi

# The image is built from the repository, on this machine, with this machine's
# toolchain -- only the *emulator* is CI's. That is the intended comparison: it
# isolates the one variable, where rebuilding inside the container would change
# the compiler as well and answer a different question.
[[ -f "$REPO_ROOT/build/bhaskix.iso" ]] || {
    echo "${YELLOW}ci-emulator${RESET}  build/bhaskix.iso not found -- run 'make iso' first" >&2
    exit 3
}

version="$(docker run --rm "$IMAGE" qemu-system-x86_64 --version 2>/dev/null | head -1)"
echo "${DIM}  $version${RESET}"
echo "${DIM}  the image was built on this machine; only the emulator is CI's${RESET}"
echo

case "$LANE" in
    all) cells=("bios max" "bios qemu64" "uefi max" "uefi qemu64") ;;
    *)   cells=("$LANE max" "$LANE qemu64") ;;
esac

status=0
for cell in "${cells[@]}"; do
    read -r lane cpu <<< "$cell"
    for ((i = 1; i <= COUNT; i++)); do
        out="$(docker run --rm -v "$REPO_ROOT:/repo" -w /repo \
            -e BHASKIX_BOOT_LOG=/tmp/lane.log \
            -e BOOT_TEST_TIMEOUT="${BOOT_TEST_TIMEOUT:-300}" \
            -e QEMU_CPU="$cpu" \
            "$IMAGE" bash -c \
            "tests/qemu/boot-test.sh $lane > /tmp/out.txt 2>&1; \
             printf '%s|%s|' \"\$?\" \"\$(grep -acE '^.\[1;32mok' /tmp/out.txt)\"; \
             grep -aE 'FAIL' /tmp/out.txt | sed 's/\x1b\[[0-9;]*m//g' | head -2 | tr '\n' ';'" \
            2>/dev/null | tail -1)"
        rc="${out%%|*}"; rest="${out#*|}"
        gates="${rest%%|*}"; failures="${rest#*|}"
        if [[ "$rc" == "0" ]]; then
            printf '  %s%-4s %-6s %-3s %s%s  %s gates\n' "$GREEN" "ok" "$lane" "$cpu" "$i" "$RESET" "$gates"
        else
            printf '  %s%-4s %-6s %-3s %s%s  %s gates -- %s\n' \
                "$RED" "FAIL" "$lane" "$cpu" "$i" "$RESET" "$gates" "$failures"
            # **The log is inside a container that has just been removed.** Said
            # out loud rather than left to be discovered: `--rm` takes the one
            # artifact worth having with it, and re-running is the only recovery.
            echo "      ${DIM}the serial log went with the container; re-run this cell to keep one${RESET}"
            status=1
        fi
    done
done

echo
if [[ $status -eq 0 ]]; then
    echo "  ${GREEN}every cell passed${RESET} on the emulator CI uses."
else
    echo "  ${RED}a cell failed${RESET} on the emulator CI uses -- which is more than local runs could ever say."
fi
exit $status
