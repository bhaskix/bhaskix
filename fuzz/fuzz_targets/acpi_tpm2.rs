// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the ACPI `TPM2` parser -- RFC 0089 step 5.
//!
//! **What is built from a believed `TPM2` is a register window a domain
//! writes to.** The table is firmware's, and the address in it becomes the
//! page `bin/tpmd` drives, so `coding-style.md` §8 makes a target mandatory
//! before the parser merges.
//!
//! # What counts as a failure
//!
//! A panic, an abort or a hang -- and one property beyond not crashing: **an
//! accepted table names a non-zero control area**, because the kernel maps
//! and grants what this returns.
//!
//! Like `dmar_parse`, every input is parsed twice: as given, and with its
//! signature, length and checksum repaired. A checksum-guarded parser is
//! otherwise unreachable past its first refusal, and the fields worth
//! fuzzing are behind it.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run acpi_tpm2 -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_arch::acpi::parse_tpm2;

/// The checksum byte's offset in an ACPI table header.
const CHECKSUM: usize = 9;

/// The shortest table `parse_tpm2` reads past: the 36-byte header, `Flags`,
/// `AddressOfControlArea` and `StartMethod`. Duplicated from the parser on
/// purpose, as `dmar_parse` explains: the target is a second opinion.
const TPM2_MIN: usize = 52;

fuzz_target!(|data: &[u8]| {
    check(data);
    if data.len() < TPM2_MIN || u32::try_from(data.len()).is_err() {
        return;
    }
    let mut table = data.to_vec();
    table[0..4].copy_from_slice(b"TPM2");
    let length = u32::try_from(table.len()).unwrap_or(u32::MAX);
    table[4..8].copy_from_slice(&length.to_le_bytes());
    table[CHECKSUM] = 0;
    let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    table[CHECKSUM] = 0u8.wrapping_sub(sum);
    check(&table);
});

fn check(bytes: &[u8]) {
    if let Some(tpm) = parse_tpm2(bytes) {
        assert!(tpm.control_area != 0, "an accepted TPM2 named address zero");
        core::hint::black_box(tpm.start_method);
    }
}
