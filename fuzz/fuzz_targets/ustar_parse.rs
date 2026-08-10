// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the `ustar` archive parser.
//!
//! The initrd is the first untrusted input this system reads: the kernel finds
//! `bin/probe`, `etc/hostname` and every other early file by walking it, before
//! there is a filesystem, a service, or a domain to contain a mistake. A parser
//! this early has no one above it to catch anything.
//!
//! `TRACKER.md` has recorded the §8 deviation for this parser since M6 — the
//! requirement was met by a seeded mutation harness, and one million blind
//! archives is a real number that is not the same assurance as guidance. The
//! ELF loader closed its half on 2026-08-10; this is the other.
//!
//! # What is exercised
//!
//! Iteration, `members`, and `lookup` — deliberately all three. Iteration is
//! where a length field decides how far to jump; `lookup` compares names and
//! then hands back a slice. A parser can be safe walking an archive and still
//! be wrong about where a member's *data* ends, which is the bug that matters,
//! because `data()` is what the caller goes on to read.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal, and not a nonsense answer:
//! random bytes are not an archive and finding nothing in them is correct. What
//! must never happen is a slice out of bounds, an offset that wraps, or an
//! iterator that never ends because a member claims a size that moves the
//! cursor backwards.
//!
//! That last one is the parser's own invariant and not this harness's to
//! enforce: `next` advances the cursor by at least a block every time round,
//! through `checked_add`, so it cannot presently run for ever. The bound below
//! caps what *this* target walks. It is not a hang detector — `members` and
//! `lookup` walk the whole archive with no bound at all, and are called
//! precisely so that a parser which ever did loop would show up as a libFuzzer
//! timeout rather than as a target that quietly stopped at 4,096.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run ustar_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_service_vfs::ustar::Archive;

fuzz_target!(|data: &[u8]| {
    // Any real initrd is far below this; an input that exceeds it is one the
    // fuzzer built to be walked, not one a caller would read.
    const MAX_MEMBERS: usize = 4096;

    let mut walked = 0usize;
    for entry in Archive::new(data) {
        // Touch what a caller touches: the name and the data slice. Walking
        // headers without reading a member proves only half of it.
        let _ = entry.name();
        let _ = entry.data();
        let _ = entry.kind();
        walked += 1;
        if walked >= MAX_MEMBERS {
            break;
        }
    }

    let archive = Archive::new(data);
    let _ = archive.members();
    let _ = archive.lookup(b"etc/hostname");
    let _ = archive.lookup(b"");
});
