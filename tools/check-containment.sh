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
#
# **The pattern moved out of this file on 2026-08-20** and now lives in
# tools/vendor-pattern.sh, which explains what it covers and what it
# deliberately does not. It moved because this script stopped being the only
# thing enforcing it: the hooks in tools/git-hooks/ refuse the commit before
# the object exists, and three copies of a pattern are three patterns. The
# fragment-assembly trick and the self-exclusion come with it -- see that file.
# shellcheck source=vendor-pattern.sh
. "$REPO_ROOT/tools/vendor-pattern.sh"
PATTERN="$VENDOR_PATTERN"

vendor=$(git ls-files 2>/dev/null | grep -vE "$VENDOR_EXEMPT" | while read -r f; do
    [[ -f "$f" ]] && grep -lniE "$PATTERN" "$f" 2>/dev/null
done)

if [[ -n "$vendor" ]]; then
    fail "AI-vendor strings found in tracked files"
    echo "$vendor" | sed 's/^/        /' >&2
else
    pass "no vendor strings in tracked files"
fi

# --- 3. git history -------------------------------------------------------
#
# This header read "SPDX headers" until 2026-08-20 -- a copy-paste that
# labelled the history scan after the section that actually follows it.
# Corrected rather than deleted, per this project's rule about wrong claims.

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
        | grep -vE "$VENDOR_EXEMPT_SUFFIX" | head -20 | sed 's/^/        /' >&2
    echo "        A file that carried this was committed and may since have been" >&2
    echo "        deleted -- the working tree being clean does not clear it." >&2
    status=1
else
    pass "no vendor strings in any file in history"
fi

# --- 4. the hooks are installed -------------------------------------------
#
# The scans above report; the hooks in tools/git-hooks/ are what actually
# prevent. A hook nobody installed prevents nothing, and its absence is
# invisible -- commits simply succeed. So the installation is itself a gate.
#
# Checked as configuration rather than by looking for files, because
# core.hooksPath is what git obeys: hooks present in the directory but not
# pointed at are decoration.
# **Skipped on CI, deliberately, and it took a red build to notice.** CI checks
# out a fresh tree and never creates a commit, so core.hooksPath is unset there
# by construction and demanding it would fail every run forever. The property
# hooks protect -- that a commit is never *created* carrying an attribution --
# belongs to developer machines. CI's backstop is the three scans above, which
# read the history a developer's hooks were supposed to keep clean, and those
# do run here.
hooks_path=$(git config --get core.hooksPath || true)
if [[ -n "${CI:-}" ]]; then
    pass "hook installation not checked on CI (no commits are created here)"
elif [[ "$hooks_path" != "tools/git-hooks" ]]; then
    fail "the vendor-attribution hooks are not installed (core.hooksPath is '${hooks_path:-unset}')"
    echo "        Run: make hooks" >&2
    echo "        Without them, the checks above can only report a string that" >&2
    echo "        is already committed -- and history cannot be edited after a" >&2
    echo "        public push." >&2
elif [[ ! -x tools/git-hooks/pre-commit || ! -x tools/git-hooks/commit-msg ]]; then
    fail "core.hooksPath is set but a hook is missing or not executable"
    echo "        Run: make hooks" >&2
else
    pass "vendor-attribution hooks installed (pre-commit, commit-msg)"
fi

# --- 5. SPDX headers ------------------------------------------------------

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
