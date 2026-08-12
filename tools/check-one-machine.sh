#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One machine, described in one place.
#
# `tests/qemu/devices.sh` holds the device list every QEMU harness boots. This
# check fails if any other harness names a device or a netdev itself.
#
# **Why a gate and not a comment.** There was a comment. `boot-test.sh` and
# `shell-test.sh` each built their own list anyway, and they drifted: one grew a
# network device and the other did not, so the shell reported holding no network
# capability — correctly, on a machine that had no network — while the boot log
# said networking worked. Both logs were true about different machines, and
# nothing could have caught it, because agreement between two lists is not
# something either list can check.
#
# A convention that two files must stay in step is a convention that will be
# broken by whoever adds the third file. This is the check that stops it being
# broken quietly.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A directory may be given, so the check can be pointed at a fixture and watched
# rejecting one. A gate nobody has seen fail is a gate nobody has tested.
HARNESSES="${1:-$REPO_ROOT/tests/qemu}"
SHARED="devices.sh"

# `-device` and `-netdev` are how a machine gains hardware. A harness that names
# either is describing a machine of its own.
PATTERN='(^|[^-[:alnum:]])-(device|netdev)[ =]'

offenders=""
for script in "$HARNESSES"/*.sh; do
    [[ "$(basename "$script")" == "$SHARED" ]] && continue
    # Comments are prose about the machine, not the machine. The point of this
    # check is what QEMU is handed, and the files here explain themselves at
    # length -- a check that could not tell an explanation from an argument
    # would make the code harder to explain, which is the wrong trade.
    if grep -nE "$PATTERN" "$script" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -q .; then
        offenders+="  $(basename "$script")"$'\n'
        grep -nE "$PATTERN" "$script" | grep -vE '^[0-9]+:[[:space:]]*#' \
            | sed 's/^/      /' >&2
    fi
done

if [[ -n "$offenders" ]]; then
    printf '  \033[1;31mFAIL\033[0m  a QEMU harness builds its own device list:\n' >&2
    printf '%s' "$offenders" >&2
    printf '        Put it in tests/qemu/%s, which every harness sources.\n' "$SHARED" >&2
    printf '        Two lists drift, and the drift is invisible from either one.\n' >&2
    exit 1
fi

printf '  \033[1;32mok\033[0m    every QEMU harness boots the machine devices.sh describes\n'
