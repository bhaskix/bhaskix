#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Every fuzz target still compiles.
#
# `fuzz/` is its own workspace on purpose -- a target links libFuzzer and needs
# a nightly sanitiser runtime, so folding it into the kernel's workspace would
# drag that into every ordinary build. The cost of that separation is that
# nothing built these targets: not `make gates`, not `make test-host`, not
# `make clippy`, not CI.
#
# **On 2026-08-18, RFC 0029 renamed `ArpCache` to `NeighbourCache` and changed
# TCP's checksum functions to take `Address` instead of `Ipv4Addr`. Two fuzz
# targets stopped compiling and nothing said so for three days.** They were not
# slow, or weak, or badly seeded. They ran zero executions, and the project
# went on describing itself as having fuzz targets on every untrusted parser.
#
# This script is why that cannot happen again. It is `cargo check`, not a
# campaign: proving a target still builds is cheap and catches the entire class,
# where running one is expensive and catches only what it happens to reach.
#
# Nightly is not required to check -- only to *run* -- so this works on the
# stable toolchain CI already has.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; RESET=$'\033[0m'

# The fuzz workspace targets the host, not the freestanding target the parent
# workspace defaults to; without this it fails on a missing `std` for a
# dependency of libfuzzer-sys rather than on anything about the target.
HOST=$(rustc -vV | sed -n 's/^host: //p')

targets=$(sed -n 's/^name = "\(.*\)"$/\1/p' fuzz/Cargo.toml | tail -n +2)
if [ -z "$targets" ]; then
    echo "  ${RED}FAIL${RESET}  no fuzz targets found in fuzz/Cargo.toml"
    exit 1
fi

status=0
broken=""
for target in $targets; do
    if ! (cd fuzz && cargo check --quiet --bin "$target" --target "$HOST" >/dev/null 2>&1); then
        broken="$broken $target"
        status=1
    fi
done

# And formatted. `make fmt` walks a hand-written list of directories and `fuzz/`
# is not on it, so a target could be committed unformatted and nothing would
# say -- which happened on 2026-08-21, to the very commit that repaired the two
# targets above. The check belongs here, with the other thing that knows this
# workspace exists, rather than as a fourteenth line on a list somebody has to
# remember to extend.
# `-p bhaskix-fuzz`, not `--all`: `cargo fmt --all` in this workspace follows
# the path dependencies and reports on `kernel/`, `net/` and everything else
# they reach -- so on 2026-08-21 this check failed with "a fuzz target is not
# formatted" over a diff in `kernel/src/vm.rs`, blaming the wrong workspace for
# a real problem. The root `make fmt` owns those crates; this owns the targets.
if [ "$status" -eq 0 ] && ! (cd fuzz && cargo fmt --check -p bhaskix-fuzz >/dev/null 2>&1); then
    echo "  ${RED}FAIL${RESET}  a fuzz target is not formatted"
    (cd fuzz && cargo fmt --check -p bhaskix-fuzz 2>&1) | head -20
    echo "        Run: cd fuzz && cargo fmt -p bhaskix-fuzz"
    status=1
fi

count=$(echo "$targets" | wc -w)
if [ "$status" -eq 0 ]; then
    printf '  %sok%s    all %d fuzz targets compile and are formatted\n' "$GREEN" "$RESET" "$count"
elif [ -n "$broken" ]; then
    # Only for a compile failure. The unformatted case has already said its
    # piece above, and printing "a target that does not compile" underneath a
    # formatting diff sends the reader after the wrong thing -- which this
    # script did on 2026-08-21, to its own author, an hour after it was written.
    for target in $broken; do
        echo "  ${RED}FAIL${RESET}  fuzz target does not compile: $target"
        (cd fuzz && cargo check --bin "$target" --target "$HOST" 2>&1) | grep -E '^error' | head -3
    done
    echo "        A target that does not compile runs zero executions and says nothing."
    echo "        Fix it in the same change that renamed what it used."
fi

exit "$status"
