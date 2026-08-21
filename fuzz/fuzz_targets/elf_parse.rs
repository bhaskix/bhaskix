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

use bhaskix_elf::{AddressHalf, for_each_relative_relocation, parse, parse_in, test_support};

/// One relocation entry is twenty-four bytes: offset, info, addend.
const ENTRY: usize = 24;

fuzz_target!(|data: &[u8]| {
    arm_raw(data);
    arm_relocations(data);
    arm_dynamic(data);
});

/// Arm A — whatever the fuzzer sent, unchanged.
///
/// The original target, and it stays because a corrupted image is what a
/// corrupted boot medium actually looks like. Every `Err` is a success here:
/// the interesting outcomes are the ones that never return at all.
fn arm_raw(data: &[u8]) {
    let _ = parse(data);
    if let Ok(image) = parse_in(data, AddressHalf::Kernel) {
        let _ = for_each_relative_relocation(data, &image, |_, _| {});
    }
}

/// Arm B — a real `ET_DYN` image whose relocation table the fuzzer wrote.
///
/// **This arm exists because the audit of 2026-08-21 measured the old target
/// and found the relocation walk was never doing anything.** Five probe points
/// were instrumented; four reached; the fifth — *a relative relocation was
/// applied* — did not, in a campaign from an empty corpus. The walk returned
/// `Ok(0)` every time, because random bytes do not carry a dynamic segment
/// naming a `RELA` table and a fuzzer cannot invent one.
///
/// So the image is built here, through `elf::test_support` — the same builder
/// the crate's own tests use, rather than a second opinion about what a
/// well-formed image looks like — and the fuzzer is given the **contents of the
/// relocation entries**, which is where the walk's decisions are: the
/// `R_X86_64_RELATIVE` check, the inside-a-segment check, and the arithmetic
/// that would let a loader write outside the image it placed.
///
/// [RFC 0036](../../docs/rfc/0036-a-relocatable-program-in-ring-3.md) makes
/// this its step 1, before any of the feature: the code that RFC depends on had
/// never been fuzzed with anything to do.
fn arm_relocations(data: &[u8]) {
    // Enough entries to exercise a table walk, few enough that one input is
    // still mostly about their contents rather than their number.
    const MAX_ENTRIES: usize = 8;

    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let entries = usize::from(count) % (MAX_ENTRIES + 1);

    // Built valid: a loadable RX segment, a dynamic segment naming a RELA
    // table, and `entries` relocations that all target one address inside the
    // image. Then the fuzzer overwrites the table.
    let mut bytes = test_support::dynamic_elf(entries, 8, test_support::BASE + 0x10);

    // Where the table is: the builder puts it last, so it is the tail.
    let table = bytes.len().saturating_sub(entries * ENTRY);
    for (slot, byte) in bytes[table..].iter_mut().zip(rest.iter().cycle()) {
        *slot = *byte;
    }

    // A parse that refuses is a correct answer -- the fuzzer may well have
    // written a table that no longer describes anything. What must not happen
    // is a panic, or an `apply` that names an address outside the image.
    let Ok(image) = parse_in(&bytes, AddressHalf::Kernel) else {
        return;
    };
    let mut applied = 0usize;
    let walked = for_each_relative_relocation(&bytes, &image, |offset, _addend| {
        applied += 1;
        // **The claim the walk makes, asserted rather than assumed.** Its own
        // comment says the target must be inside a loaded segment's memory
        // span, "or the loader would write outside the image it placed" -- so
        // an `apply` that named an address outside every segment would be the
        // walk handing a loader a write it promised not to.
        let inside = image.segments().any(|segment| {
            offset >= segment.address
                && offset
                    .checked_add(8)
                    .is_some_and(|end| end <= segment.address.saturating_add(segment.memory_size))
        });
        assert!(
            inside,
            "a relocation named {offset:#x}, outside every segment"
        );
    });

    if let Ok(count) = walked {
        // Everything it counted, it applied. A walk that returned a count
        // larger than the number of callbacks would mean entries were skipped
        // silently, which is how a loader ends up with a half-relocated image.
        assert_eq!(count, applied, "the walk counted more than it applied");
    }
}

/// Arm C — the dynamic table itself, written by the fuzzer.
///
/// Arm B attacks the relocation entries behind a valid dynamic segment; this
/// attacks the segment that *finds* them. `DT_RELA`, `DT_RELASZ` and
/// `DT_RELAENT` are three attacker-chosen numbers that between them say where
/// a table is, how big it is, and how big an entry is — and the walk's refusals
/// for each (an entry size that is not 24, a size that is not a multiple of it,
/// an address that resolves to no file offset) are only reachable through here.
fn arm_dynamic(data: &[u8]) {
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let entries = usize::from(count) % 5;
    let mut bytes = test_support::dynamic_elf(entries, 8, test_support::BASE + 0x10);

    // The dynamic table sits between the program headers and the relocations:
    // four (tag, value) pairs, sixty-four bytes. The builder's layout puts it
    // immediately after the two program headers.
    const PHOFF: usize = 64;
    const PHENTSIZE: usize = 56;
    let dynamic = PHOFF + 2 * PHENTSIZE;
    let end = (dynamic + 64).min(bytes.len());
    for (slot, byte) in bytes[dynamic..end].iter_mut().zip(rest.iter().cycle()) {
        *slot = *byte;
    }

    let Ok(image) = parse_in(&bytes, AddressHalf::Kernel) else {
        return;
    };
    let _ = for_each_relative_relocation(&bytes, &image, |offset, _| {
        let inside = image.segments().any(|segment| {
            offset >= segment.address
                && offset
                    .checked_add(8)
                    .is_some_and(|end| end <= segment.address.saturating_add(segment.memory_size))
        });
        assert!(
            inside,
            "a relocation named {offset:#x}, outside every segment"
        );
    });
}
