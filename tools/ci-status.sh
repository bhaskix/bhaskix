#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# What CI thinks of `main`, and which job -- and which step of it -- says so.
#
# Usage:  tools/ci-status.sh [count]        # default 12 pushes
#         tools/ci-status.sh --budgets      # what the newest run's lanes measured
#
# # Why this exists
#
# CI was **red on `main` for sixteen consecutive commits** across 2026-08-23 and
# 24 -- runs 289 to 304 -- and nobody learned it until somebody went looking for
# an unrelated bug. `rustfmt` broke first, `clippy` joined it two commits later
# behind a duplicated `#[rustfmt::skip]`, and the `rustfmt` half was then healed
# by accident when an unrelated change ran `cargo fmt --all`, leaving one red job
# quietly on its own for another eight commits.
#
# It had happened before. `TRACKER.md`'s changelog records "CI green" being
# asserted from 2026-08-14 to 2026-08-16 while both `qemu64` boot lanes were red.
# Twice is a process, not an accident.
#
# # And the thing that made it invisible was a belief, not a limit
#
# `TRACKER.md` recorded a blocker: *"Reading Actions logs needs authentication;
# unauthenticated API gives 60 requests/hour and only pass/fail."* Both halves
# are true and the conclusion drawn from them was wrong. Pass/fail is available
# **per job and per step**, unauthenticated, and the name of the failing job is
# nearly all of the diagnosis: `clippy` red and every other job green points at
# one command a developer can run locally in seconds. What authentication buys
# is the *log*, which is the last mile, not the first.
#
# **The step names were free too, and this tool did not ask for them until
# 2026-08-25.** The same belief that hid the job names one level up hid the
# steps one level down: a docs-only commit turned `boot (uefi, qemu64)` red, and
# "the boot lane failed" does not say whether it failed building, installing
# QEMU, or asserting on serial output -- three different problems. It failed
# asserting, which is the one that means "a gate went red", and the lane then
# passed three times out of three locally.
#
# So this script asks for exactly what is free, and says plainly when the answer
# is rate-limited rather than printing an empty table and letting silence read as
# success -- which is the failure mode it exists to end.
#
# `make gates` deliberately does not call this: a check that needs the network
# is not a gate, and a gate that passes when GitHub is unreachable is worse than
# no gate. This is a thing a person runs.

set -uo pipefail

REPO="${BHASKIX_CI_REPO:-bhaskix/bhaskix}"
BUDGETS=0
[[ ${1:-} == "--budgets" ]] && { BUDGETS=1; shift; }
COUNT="${1:-12}"
API="https://api.github.com/repos/$REPO/actions"
CHECKS="https://api.github.com/repos/$REPO"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; DIM=$'\033[2m'; RESET=$'\033[0m'

command -v curl >/dev/null 2>&1 || { echo "ci-status: needs curl" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "ci-status: needs python3" >&2; exit 2; }

fetch() { curl -sS -m 30 -H 'Accept: application/vnd.github+json' "$1" 2>/dev/null; }

runs_json="$(fetch "$API/runs?per_page=60&branch=main&event=push")"

# Three failure modes, told apart, because "no output" must never read as
# "nothing is wrong".
case "$runs_json" in
    "")   echo "${YELLOW}ci-status${RESET}  GitHub unreachable -- this says nothing about CI" >&2; exit 3 ;;
    # **Two wildcards, not a literal `": "`.** This arm was written expecting
    # `"message": "API rate limit exceeded` and GitHub sends `"message":"API
    # rate limit exceeded` -- no space -- so it never matched, and a
    # rate-limited run fell through to the vaguer "no ci runs returned" below.
    # Both are honest and neither claims CI is green, but one tells you to wait
    # an hour and the other sends you looking for a broken workflow. The `Not
    # Found` arm below already had the wildcard and was already right.
    *'"message":'*'API rate limit exceeded'*)
          echo "${YELLOW}ci-status${RESET}  rate-limited (60/hour unauthenticated) -- try later" >&2; exit 3 ;;
    *'"message":'*'Not Found'*)
          echo "${YELLOW}ci-status${RESET}  no such repository: $REPO" >&2; exit 3 ;;
esac

# The run list first: cheap, one request, and it already answers "is main green".
mapfile -t failing < <(printf '%s' "$runs_json" | COUNT="$COUNT" python3 -c '
import json, os, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
runs = [r for r in data.get("workflow_runs", []) if r.get("name") == "ci"]
runs.sort(key=lambda r: -r["run_number"])
count = int(os.environ["COUNT"])
for r in runs[:count]:
    print("\t".join([
        str(r["run_number"]),
        str(r.get("conclusion") or r.get("status") or "?"),
        r["head_sha"][:7],
        r["created_at"][:10],
        (r.get("display_title") or "")[:56],
        str(r["id"]),
    ]))
')

if [[ ${#failing[@]} -eq 0 ]]; then
    echo "${YELLOW}ci-status${RESET}  no ci runs returned -- this says nothing about CI" >&2
    exit 3
fi

printf '%s\n' "${DIM}  run  result      sha       when         title${RESET}"
red_ids=()
streak=0
counting=1
for line in "${failing[@]}"; do
    IFS=$'\t' read -r num conclusion sha when title id <<< "$line"
    case "$conclusion" in
        success)     mark="${GREEN}pass${RESET}    "; counting=0 ;;
        failure)     mark="${RED}FAIL${RESET}    "; red_ids+=("$num:$id")
                     [[ $counting -eq 1 ]] && streak=$((streak + 1)) ;;
        in_progress|queued|None|"") mark="${DIM}...${RESET}     " ;;
        *)           mark="${YELLOW}$conclusion${RESET}" ;;
    esac
    printf '%5s  %b  %s   %s   %s\n' "$num" "$mark" "$sha" "$when" "$title"
done

# Then, and only for the runs that failed, which job failed. One request each,
# so the loop is bounded -- the unauthenticated budget is 60 an hour and this
# script is not the only thing that may want it.
if [[ ${#red_ids[@]} -gt 0 ]]; then
    echo
    echo "${DIM}  which job says so (the part that was thought to need a token):${RESET}"
    shown=0
    for entry in "${red_ids[@]}"; do
        [[ $shown -ge 6 ]] && { echo "${DIM}    ... $(( ${#red_ids[@]} - shown )) older failing runs not queried${RESET}"; break; }
        num="${entry%%:*}"; id="${entry##*:}"
        jobs_json="$(fetch "$API/runs/$id/jobs")"
        names="$(printf '%s' "$jobs_json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
# The failing job, **and the step inside it that failed**. Step conclusions
# come back on the same unauthenticated request the job names do -- one more
# notch of diagnosis for free. A job name says "the boot lane"; a step name
# says whether it failed building, installing QEMU, or asserting on serial
# output, and those are three different problems.
bad = []
for j in data.get("jobs", []):
    if j.get("conclusion") in ("success", None):
        continue
    steps = [
        s.get("name", "?")
        for s in (j.get("steps") or [])
        if s.get("conclusion") not in ("success", "skipped", None)
    ]
    bad.append(j["name"] + (" -- " + "; ".join(steps) if steps else ""))
print(", ".join(bad))
')"
        if [[ -n "$names" ]]; then
            printf '    run %-5s %s%s%s\n' "$num" "$RED" "$names" "$RESET"
        else
            printf '    run %-5s %s(job list unavailable -- rate limit?)%s\n' "$num" "$DIM" "$RESET"
        fi
        shown=$((shown + 1))
    done

    # **And what the gate actually said**, which used to need a token and now
    # does not.
    #
    # The harnesses emit every failed assertion as `::error::`, so its text
    # becomes an annotation, and annotation text comes back on the same
    # unauthenticated request as everything else here. Job logs answer 403 and
    # artifacts answer 401; this is the one channel that does not.
    #
    # Run 446 of 2026-08-30 is the case for it: a docs-only commit turned
    # `boot (bios, qemu64)` red, the boot log was uploaded *specifically* so it
    # could be read, and nobody without credentials could read it. Fifteen local
    # runs of that lane did not reproduce it, so the log was the only evidence
    # there was.
    #
    # Only for the newest failing run, and only when something is red: two more
    # requests against a 60-an-hour budget, spent at the moment they are worth
    # most.
    newest_red_sha="$(printf '%s' "${failing[0]}" | cut -f3)"
    if [[ -n "$newest_red_sha" ]]; then
        red_checks="$(fetch "$CHECKS/commits/$newest_red_sha/check-runs?per_page=30")"
        red_ann_ids="$(printf '%s' "$red_checks" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in data.get("check_runs", []):
    if r.get("conclusion") == "failure" and (r.get("output") or {}).get("annotations_count", 0):
        print(r["id"])
')"
        printed_any=0
        for id in $red_ann_ids; do
            said="$(fetch "$CHECKS/check-runs/$id/annotations" | python3 -c '
import json, sys
try:
    anns = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(anns, list):
    sys.exit(0)
for a in anns:
    if a.get("annotation_level") != "failure":
        continue
    msg = (a.get("message") or "").strip()
    # The runner adds this one itself for any non-zero exit. It says nothing
    # the result line has not already said, and printing it would bury the
    # annotations that do.
    if not msg or msg.startswith("Process completed with exit code"):
        continue
    print("      " + msg[:160])
')"
            if [[ -n "$said" ]]; then
                [[ $printed_any -eq 0 ]] && {
                    echo
                    echo "${DIM}  what the gate said (annotations, no token needed):${RESET}"
                }
                printf '%s%s%s\n' "$RED" "$said" "$RESET"
                printed_any=1
            fi
        done
        if [[ $printed_any -eq 0 ]]; then
            echo
            echo "${DIM}  no gate text -- the run predates the ::error:: annotations, or"
            echo "  the failure was not an assertion (a build, a timeout, the runner)${RESET}"
        fi
    fi
fi

# **What each lane measured, which is readable without a token after all.**
#
# The harnesses print the fraction of their timeout a *passing* run used, and on
# CI that went into a job log, which does need authentication -- so the one
# number worth having was produced where nobody could read it. Emitting it as a
# workflow `::notice::` puts it in the run's **annotations**, and those come back
# on the same unauthenticated requests everything else here uses.
#
# Behind a flag rather than always, because it costs one request per check run
# with annotations and this script is careful with a 60-an-hour budget on
# purpose.
#
# What it answered the first time it was asked, 2026-08-25: `bios` 30.926s and
# `uefi` 33.927s on CI against 30.1-32.6s and 37.1-39.4s on the machine this was
# written on. **The runner is the same speed**, which killed the theory that the
# boot lanes were timing out -- they were at a quarter of the old budget.
if [[ $BUDGETS -eq 1 ]]; then
    head_sha="$(printf '%s' "${failing[0]}" | cut -f3)"
    echo
    echo "${DIM}  what each lane measured (newest run, $head_sha):${RESET}"
    checks_json="$(fetch "$CHECKS/commits/$head_sha/check-runs?per_page=30")"
    ids="$(printf '%s' "$checks_json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in data.get("check_runs", []):
    if (r.get("output") or {}).get("annotations_count", 0):
        print(r["id"])
')"
    if [[ -z "$ids" ]]; then
        echo "${DIM}    none reported -- rate limit, or the run predates the notices${RESET}"
    else
        for id in $ids; do
            fetch "$CHECKS/check-runs/$id/annotations" | python3 -c '
import json, sys
try:
    anns = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(anns, list):
    sys.exit(0)
for a in anns:
    if a.get("annotation_level") != "notice":
        continue
    # Assembled rather than f-stringed. This runs inside a single-quoted shell
    # heredoc, so the inner quotes an f-string needs cannot be escaped -- and a
    # backslash inside an f-string expression is a SyntaxError regardless.
    # Found by running the fragment on its own before shipping it, which is the
    # only reason this is not a broken flag nobody discovers until the hour they
    # need it. (No apostrophes here either, for the same heredoc reason.)
    title = a.get("title") or ""
    message = a.get("message") or ""
    print("    " + title + ": " + message)
'
        done
    fi
fi

echo
if [[ $streak -gt 0 ]]; then
    echo "  ${RED}main is red${RESET}, and has been for ${RED}$streak${RESET} consecutive push$([[ $streak -eq 1 ]] || echo es)."
    exit 1
fi
echo "  ${GREEN}main is green${RESET} at the newest completed run."
