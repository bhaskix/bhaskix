// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the ELF64 loader's parser.
//!
//! `docs/coding-style.md` §8 asks for a fuzz target on every untrusted parser,
//! and `TRACKER.md` has recorded a deviation ever since M6-03: the requirement
//! was met by a *seeded* mutation harness, which explores blindly. Coverage
//! guidance is what finds the branch that needs four specific bytes in the
//! right places, and a million blind archives is a real number that is not the
//! same assurance. This closes that gap; the seeded harness stays, because it
//! runs in CI in twenty milliseconds and this does not.
//!
//! [`bhaskix_elf::parse`] is the whole attack surface reachable from a
//! byte buffer: it validates an image without mapping anything, which is why it
//! was split out from `load_into` in the first place.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a rejection — a parser handed random
//! bytes should reject nearly all of them, and `ElfError` is the correct
//! outcome, not a finding. What must never happen is an arithmetic overflow, an
//! out-of-bounds read, or an unbounded loop on a length the header chose.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run elf_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The result is deliberately ignored. Every `Err` is a success: the
    // interesting outcomes are the ones that never return at all.
    let _ = bhaskix_elf::parse(data);
    // The kernel-half parse and the relocation walk are the boot loader's
    // path through the same crate; fuzzing them here is what step 4's
    // extraction bought.
    if let Ok(image) = bhaskix_elf::parse_in(data, bhaskix_elf::AddressHalf::Kernel) {
        let _ = bhaskix_elf::for_each_relative_relocation(data, &image, |_, _| {});
    }
});
