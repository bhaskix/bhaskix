# SPDX-License-Identifier: Apache-2.0
#
# The per-boot readings every QEMU harness copies into its job log.
#
# **Why this file exists.** A passing boot's serial never reaches the CI log,
# so every per-boot counter this tree prints was invisible in CI unless the
# boot failed: measured 2026-09-29, 56 passing boot and shell jobs across runs
# 758-767 and **not one** carried the raised-versus-delivered line the
# undelivered-signal row's fix needed a rate from. `boot-test.sh` began
# copying a few lines into its job log, prefixed `reading`, pass or fail, and
# `tools/ci-readings.py` tallies them.
#
# The nightly soak boots twenty times and printed none of them: it runs QEMU
# itself and uploads its logs **only when it fails**, so a passing soak left
# nothing behind at all. Found 2026-09-30, when `ci-readings.py`'s comment
# claimed every soak boot kept its serial as an artifact and the artifact
# listing of a passing run was empty. One pattern in one place, for the same
# reason `devices.sh` is one list: two copies drift, and a reading one harness
# prints and the other does not is a tally that silently changes denominator.
#
# **Colour stripped first**, because a line the kernel prints in yellow starts
# with an escape and not with spaces, and was copied without its prefix -- so
# `ci-readings.py` never saw it. Found on `linux park`, which is always yellow;
# `hosted signals` turns yellow exactly when raised and delivered disagree,
# which is the one reading that would have vanished when it mattered.

READINGS_PATTERN='hosted signals +[0-9]+ raised, [0-9]+ delivered|identity +[0-9]+ read\(s\) of the running thread|domains +capabilities [0-9]+ live before|hosted timed +[0-9]+ timed wait|ipc handover\* +[0-9]+ rendezvous dropped|tcpd served\* +[0-9]+ call\(s\) dequeued|tcpd send\* +[0-9]+ byte\(s\) held unsent|hosted deliver +[0-9]+ delivered as the call was made|linux park +the nucleus answered|linux park +[0-9]+ parks refused|deadline slots +[0-9]+ arm\(s\) refused|deadline arms\* +[0-9]+ armed from ring 3'

# Prints the readings in serial log `$1`, one per line, prefixed `reading`.
print_readings() {
    grep -aE "$READINGS_PATTERN" "$1" \
        | sed -E 's/\x1b\[[0-9;]*m//g; s/^ +/reading  /' || true
}
