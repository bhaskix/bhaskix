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

# Git history is the part that cannot be fixed later. A file can be edited; a
# commit message, an author field, a tag or a branch name that has been pushed
# to a public repository is permanent, mirrored, and indexed. So the whole
# history is checked on every run, not just the working tree.
#
# **This said "the whole history" and checked only the metadata** until
# 2026-08-11, when an audit of this script went looking for what it could not
# catch. A vendor string committed inside a *file* and deleted in a later commit
# passed every check here: the tracked-file scan below sees only what the
# working tree has now, and the metadata scan sees only messages, authors, tags
# and refs. The blob scan added below closes that, and the repository was clean
# when it was written -- 167 commits, no hit.
history=$(
    {
        git log --all --format='%s%n%b%n%an%n%ae%n%cn%n%ce' 2>/dev/null
        git tag -l 2>/dev/null
        git tag -l --format='%(contents)' 2>/dev/null
        git for-each-ref --format='%(refname)' 2>/dev/null
    } | grep -niE "$PATTERN" || true
)

if [[ -n "$history" ]]; then
    fail "vendor strings found in git history (commit messages, authors, refs)"
    echo "$history" | head -20 | sed 's/^/          /' >&2
    echo "        History cannot be edited after a public push. If this is a" >&2
    echo "        local-only commit, rewrite it now; if it is already pushed," >&2
    echo "        the repository has to be rewritten and force-pushed." >&2
    status=1
else
    pass "no vendor strings in git history"
fi

# Every version of every file that has ever been committed, by scanning the
# blobs rather than the commits.
#
# Deduplicated, and that is what makes it affordable: a file unchanged across a
# hundred commits is one blob, so this is O(distinct file versions) where
# `git grep` over `rev-list` is O(commits x tree). Measured at 167 commits:
# 245 ms this way, 5.3 s the other -- less than the rest of this script costs.
#
# The fast path only answers *whether*. Naming the file and the commit is left
# to the slow walk below, which runs only when there is something to name --
# paying for a diagnosis nobody needs is how a cheap gate becomes one that gets
# skipped.
blobs=$(git rev-list --all --objects 2>/dev/null | awk '{print $1}' \
    | git cat-file --batch-check='%(objectname) %(objecttype)' 2>/dev/null \
    | awk '$2 == "blob" { print $1 }' \
    | git cat-file --batch 2>/dev/null \
    | grep -icE "$PATTERN")

if [[ "$blobs" -gt 0 ]]; then
    fail "vendor strings found in a file somewhere in history"
    git grep -liE "$PATTERN" $(git rev-list --all) -- . 2>/dev/null \
        | grep -v 'tools/check-containment.sh$' | head -20 | sed 's/^/        /' >&2
    echo "        A file that carried this was committed and may since have been" >&2
    echo "        deleted -- the working tree being clean does not clear it." >&2
    status=1
else
    pass "no vendor strings in any file in history"
fi

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
