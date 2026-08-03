#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Enforces two invariants that review reliably misses.
#
# 1. Bootloader containment (docs/architecture.md §1)
#    Only boot/shim/ may name Limine. This is what makes replacing it with
#    bhaskixboot.efi in Phase 2 a shim rewrite rather than a kernel rewrite.
#    The invariant decays silently -- one `use limine::` in a driver and the
#    coupling is back -- so it is checked mechanically.
#
# 2. No AI-vendor strings in published files (project policy).
#
# Both are cheap. Run on every PR.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

status=0
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; status=1; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }

# --- 1. bootloader containment -------------------------------------------

# boot/ is the boundary: boot/handoff explains in prose why it exists, and
# boot/shim implements it. Everything above -- the nucleus and the services --
# must not know a bootloader exists.
offenders=$(grep -rniE '\blimine\b' \
    --include='*.rs' --include='*.toml' \
    . 2>/dev/null \
    | grep -v '^\./boot/' \
    | grep -v '^\./target/')

if [[ -n "$offenders" ]]; then
    fail "Limine is named outside boot/ -- see docs/architecture.md §1"
    echo "$offenders" | sed 's/^/        /' >&2
else
    pass "bootloader containment: only boot/ names Limine"
fi

# --- 2. vendor strings ----------------------------------------------------

# Local tooling context is excluded via .git/info/exclude and is never
# published, so it is not scanned here.
# The pattern is assembled from fragments and this script excludes itself,
# because it is necessarily the one tracked file that contains the strings it
# is looking for.
PATTERN="cla""ude|anthro""pic"
vendor=$(git ls-files 2>/dev/null | grep -v '^tools/check-containment.sh$' | while read -r f; do
    [[ -f "$f" ]] && grep -lniE "$PATTERN" "$f" 2>/dev/null
done)

if [[ -n "$vendor" ]]; then
    fail "AI-vendor strings found in tracked files"
    echo "$vendor" | sed 's/^/        /' >&2
else
    pass "no vendor strings in tracked files"
fi

# --- 3. SPDX headers ------------------------------------------------------

missing=$(git ls-files '*.rs' '*.sh' '*.py' 2>/dev/null | while read -r f; do
    [[ -f "$f" ]] || continue
    head -3 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || echo "$f"
done)

if [[ -n "$missing" ]]; then
    fail "missing SPDX-License-Identifier header (RFC 0001)"
    echo "$missing" | sed 's/^/        /' >&2
else
    pass "every source file carries an SPDX header"
fi

exit $status
