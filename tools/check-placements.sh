#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the placement table (RFC 0013).
#
# The claim RFC 0013 makes is that a service can be moved between the nucleus
# and its own domain by changing one line in `services.toml`. That claim is
# worth nothing unless something enforces the property it rests on: a service
# must not be able to reach into the kernel, in either placement.
#
# The enforcement here is the dependency graph, not a search for suspicious
# lines. A service crate cannot name `crate::vfs` — or anything else in the
# kernel — without depending on the kernel, so the resolved graph is the whole
# answer and it cannot be worked around by spelling something differently.
#
# On top of that, every relocatable service is *built* with no kernel in the
# build at all. That is the domain placement's compile, and unlike a lint it
# cannot pass by accident.
#
# Usage: check-placements.sh [table]
#
# The table argument is for the negative fixture, which runs through exactly
# this code path so that what the fixture proves is what the check does.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

TABLE="${1:-services.toml}"
TARGET="x86_64-unknown-none"

# What a service crate is allowed to reach. Adding to this list is a design
# decision about every service at once, which is why it is three lines long
# and in a file people read.
# `bhaskix-ustar` joined the list at RFC 0030 step 1: it is the parser the
# VFS always contained, extracted to the leaf layer, and it depends on
# nothing -- a service reaching it holds no more authority than before.
ALLOWED="bhaskix-abi bhaskix-service bhaskix-ustar"

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
OFF=$'\033[0m'
fail=0

ok()  { printf '%sok%s    %s\n' "$GREEN" "$OFF" "$1"; }
bad() { printf '%sFAIL%s  %s\n' "$RED" "$OFF" "$1"; fail=1; }

if [[ ! -f $TABLE ]]; then
    bad "placement table $TABLE does not exist"
    exit 1
fi

# Reads one field out of the current [[service]] block. The table is ours and
# its shape is fixed, so this stays a small awk program rather than becoming a
# reason to want a TOML parser in the build.
fields() {
    awk '
        /^\[\[service\]\]/ { if (n) print rec; rec = ""; n = 1; next }
        /^[a-z_]+ *=/ {
            key = $1
            sub(/^[^=]*= */, "")
            gsub(/"/, "")
            sub(/ *#.*/, "")
            sub(/ +$/, "")
            rec = rec key "=" $0 ";"
        }
        END { if (n) print rec }
    ' "$TABLE"
}

field() { sed -n "s/.*[;^]\?${2}=\([^;]*\);.*/\1/p" <<<";$1"; }

count=0
seen=""
while IFS= read -r record; do
    [[ -z $record ]] && continue
    count=$((count + 1))

    name=$(field "$record" name)
    placement=$(field "$record" placement)
    crate=$(field "$record" crate)
    package=$(field "$record" package)
    relocatable=$(field "$record" relocatable)

    if [[ -z $name || -z $placement || -z $crate || -z $package ]]; then
        bad "a [[service]] entry is missing a field: $record"
        continue
    fi

    case $placement in
        nucleus | domain) ;;
        *) bad "$name: placement '$placement' is neither nucleus nor domain" ;;
    esac

    # Checked after the row has been judged on its own terms, not before: the
    # first version of this script skipped the duplicate row outright, so a
    # table with a repeated name *and* a bogus placement reported one problem
    # and hid the other -- a check that stops at the first thing it finds
    # reports the count of its own control flow rather than of the mistakes.
    #
    # A name twice is worse than a name missing: two rows for one service
    # means one of them decides the placement and nobody can tell which, and
    # the boot line would agree with whichever the parser happened to keep.
    if [[ " $seen " == *" $name "* ]]; then
        bad "$name: listed twice — one of the two rows would silently decide the placement"
        continue
    fi
    seen="$seen $name"

    manifest="$crate/Cargo.toml"
    if [[ ! -f $manifest ]]; then
        bad "$name: no crate at $crate"
        continue
    fi

    if ! grep -q "^name = \"$package\"" "$manifest"; then
        bad "$name: $manifest is not $package"
        continue
    fi

    if [[ $relocatable != true ]]; then
        ok "$name: $placement, in $package, not relocatable yet (declared)"
        continue
    fi

    # The dependency rule, against the resolved graph.
    # Stderr goes nowhere on purpose: cargo narrates ("Locking 4 packages") on
    # it, and a progress line read as a package name would put a word in the
    # failure message that is not a dependency of anything.
    if ! tree=$(cargo tree --manifest-path "$manifest" --edges normal --prefix none 2>/dev/null); then
        bad "$name: cannot resolve dependencies of $package"
        continue
    fi

    reached=""
    while read -r crate_name _; do
        [[ -z $crate_name || $crate_name == "$package" ]] && continue
        [[ " $ALLOWED " == *" $crate_name "* ]] && continue
        [[ $reached == *" $crate_name"* ]] && continue
        reached="$reached $crate_name"
    done <<<"$tree"

    if [[ -n $reached ]]; then
        # The message names the dependency, because "this service is not
        # relocatable" is not an actionable sentence and "it reaches
        # bhaskix-kernel" is.
        bad "$name: reaches$reached — a service may only reach: $ALLOWED"
        continue
    fi
    ok "$name: reaches nothing but $ALLOWED"

    # And it builds with no kernel in the build. This is the part a lint
    # cannot do: the compile either works without the nucleus or it does not.
    if cargo build --quiet --manifest-path "$manifest" --target "$TARGET" 2>/dev/null; then
        ok "$name: builds standalone for $TARGET (the domain placement's compile)"
    else
        bad "$name: does not build standalone for $TARGET"
    fi

    # Cheap cross-check that the table and the code agree on the name. The
    # boot gate is the real one; this one catches a rename that only got
    # halfway.
    if ! grep -rq "const NAME: &'static str = \"$name\"" "$crate/src"; then
        bad "$name: no service in $crate declares that name"
    else
        ok "$name: the crate declares the name the table uses"
    fi
done < <(fields)

if [[ $count -eq 0 ]]; then
    bad "$TABLE lists no services — an empty table would pass every check below"
fi

exit $fail
