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

count=$(echo "$targets" | wc -w)
if [ "$status" -eq 0 ]; then
    printf '  %sok%s    all %d fuzz targets still compile\n' "$GREEN" "$RESET" "$count"
else
    for target in $broken; do
        echo "  ${RED}FAIL${RESET}  fuzz target does not compile: $target"
        (cd fuzz && cargo check --bin "$target" --target "$HOST" 2>&1) | grep -E '^error' | head -3
    done
    echo "        A target that does not compile runs zero executions and says nothing."
    echo "        Fix it in the same change that renamed what it used."
fi

exit "$status"
