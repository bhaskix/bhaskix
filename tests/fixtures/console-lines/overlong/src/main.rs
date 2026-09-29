// SPDX-License-Identifier: Apache-2.0
//! A fixture for `tools/check-console-lines.py`, which must refuse it: one
//! line fits, the other is 329 bytes -- the shape of `bin/sup`'s report line
//! that a kernel print split on 2026-09-29.

fn report() {
    write(b"fits: a short line\n");
    write(
        b"sup: supervised a running child -- mapped a page into it, wrote a word across, \
read it back, and was refused an unmapped address, a domain it \
does not hold, an oversized copy, a capability that is not a domain, a protection that \
does not exist, a thread that is not its own, and a second program in a domain that \
already has one\n",
    );
}
