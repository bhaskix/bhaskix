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

# **And every device's drive is declared beside it.**
#
# The check above catches a harness that names a *device*. It did not catch a
# device in `devices.sh` whose `-drive` was added to one harness only, which is
# the same drift one level down: `-device ide-hd,drive=sata0` shipped while
# `sata0` was declared in `boot-test.sh` alone, so `shell-test.sh` booted a
# machine QEMU refused to start and fifty-two checks failed without naming why
# (RFC 0046 step 4, 2026-08-24).
#
# So: every `drive=NAME` in the shared file must have a matching `id=NAME` in
# the same file. Self-contained, which is the only kind of agreement one file
# can check.
# The two virtio disks are **named here on purpose and not an oversight.** They
# predate this file: every harness declares its own, because some of them make
# their own copies -- the soak regenerates both between runs, and a shared
# declaration would have many machines writing one image. So the rule this check
# enforces is narrower than "all drives live here": it is that a drive *this
# file's devices introduce* is declared where the device is. Unifying disk0 and
# disk1 would be the wider fix and is not this step's.
EXEMPT="disk0 disk1"

missing=""
shared_file="$HARNESSES/$SHARED"
if [[ -f "$shared_file" ]]; then
    body="$(grep -vE '^[[:space:]]*#' "$shared_file")"
    for name in $(printf '%s' "$body" | grep -oE 'drive=[A-Za-z0-9_]+' | cut -d= -f2 | sort -u); do
        case " $EXEMPT " in *" $name "*) continue ;; esac
        if ! printf '%s' "$body" | grep -qE "id=$name([,\"[:space:]]|\$)"; then
            missing+="  drive=$name is named by a device and declared by nothing"$'\n'
        fi
    done
fi

if [[ -n "$missing" ]]; then
    printf '  \033[1;31mFAIL\033[0m  a device names a drive that %s does not declare:\n' \
        "$SHARED" >&2
    printf '%s' "$missing" >&2
    printf '        A -device here whose -drive lives in a harness is the same drift\n' >&2
    printf '        this file exists to stop, one level down.\n' >&2
    exit 1
fi

if [[ -n "$offenders" ]]; then
    printf '  \033[1;31mFAIL\033[0m  a QEMU harness builds its own device list:\n' >&2
    printf '%s' "$offenders" >&2
    printf '        Put it in tests/qemu/%s, which every harness sources.\n' "$SHARED" >&2
    printf '        Two lists drift, and the drift is invisible from either one.\n' >&2
    exit 1
fi

printf '  \033[1;32mok\033[0m    every QEMU harness boots the machine devices.sh describes\n'
