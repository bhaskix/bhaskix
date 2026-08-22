# SPDX-License-Identifier: Apache-2.0
#
# The one definition of the forbidden-attribution pattern. Sourced by
# tools/check-containment.sh and by the hooks in tools/git-hooks/.
#
# It lives in its own file for one reason: three copies of a pattern are three
# patterns, and the day they disagree is the day the weakest one is the rule.
# Anything that enforces this must source this file rather than spell it out.
#
# **Every string below is assembled from fragments**, so this file does not
# itself contain any of the words it forbids. That is not decoration -- without
# it, the checks would have to special-case their own definition, and a scan
# that skips a file is a scan with a hole in it. The files that must still be
# exempted are listed in VENDOR_EXEMPT, and that list is deliberately short.

# --- what is forbidden ----------------------------------------------------
#
# AI-vendor names. Bhaskix is presented as independent systems work; an
# attribution to any model vendor, in any file, commit message, tag or ref,
# undercuts that and cannot be removed once pushed.
VENDOR_PATTERN="cla""ude|anthro""pic|chat""gpt|open""ai|copil""ot|gem""ini|mistr""al"

# --- what is deliberately NOT forbidden, and why --------------------------
#
# Bare model words -- "opus", "sonnet", "haiku", "fable", "llama" -- are
# ordinary English and a kernel tree may one day use them innocently. They are
# not in the pattern. The leak they would represent is an *attribution*, and an
# attribution in a commit message is caught by the trailer ban in
# tools/git-hooks/commit-msg regardless of which name it carries. That is the
# tighter check: it catches the shape rather than guessing the vocabulary.
#
# Bare "gpt" is excluded on purpose. This is a UEFI project; GPT is the GUID
# Partition Table, and a partition parser is plausible future work in
# boot/bhaskixboot. The vendor spelling is covered above.
#
# **Trigger to revisit:** a leak that gets past this, or an AI vendor whose
# name is not listed appearing in a proposed commit. Add the name here, in one
# place, and every enforcement point picks it up.

# --- the files allowed to contain these strings ---------------------------
#
# Necessarily the enforcement machinery itself. Nothing else is ever added to
# this list without the same justification: that the file's job is to name what
# is forbidden. A documentation file describing the rule must describe it
# *without* the words -- CONTRIBUTING.md does exactly that.
#
# Two spellings of the same list, because they are matched against two
# different shapes and one regex cannot serve both:
#
#   VENDOR_EXEMPT         paths as `git ls-files` prints them  -- `tools/x.sh`
#   VENDOR_EXEMPT_SUFFIX  paths as `git grep <rev>` prints them -- `abc123:tools/x.sh`
#
# The second is not anchored at the start for exactly that reason. An anchored
# pattern silently matches nothing against a prefixed path, which would leave
# the history diagnostic naming its own machinery as an offender.
VENDOR_EXEMPT_FILES='tools/(vendor-pattern\.sh|check-containment\.sh|git-hooks/(pre-commit|commit-msg))'
VENDOR_EXEMPT="^${VENDOR_EXEMPT_FILES}\$"
VENDOR_EXEMPT_SUFFIX="${VENDOR_EXEMPT_FILES}\$"
