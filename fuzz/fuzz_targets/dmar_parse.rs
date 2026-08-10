// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the `DMAR` table parser.
//!
//! **The one whose failure mode is worst**, which is why RFC 0012 asked for a
//! fuzz target on it specifically. Firmware supplies this table, the kernel
//! believes it, and what is built from it is a *register window written to as
//! if it were an IOMMU*. A wrong base address here is not a wrong answer; it is
//! stores landing somewhere that is not the unit, on the code path whose entire
//! job is containing devices.
//!
//! A seeded mutation harness has covered it since M6-10. `TRACKER.md` records
//! that as weaker than `coding-style.md` §8 intends, and the ELF loader put a
//! number on the gap on 2026-08-10: guidance found 2,054 inputs reaching paths
//! twelve billion blind mutations never did.
//!
//! # The checksum is a wall, and the harness has to climb it
//!
//! An ACPI table carries a checksum over **every byte of the table**, and
//! `parse_dmar` refuses anything that does not sum to zero — correctly, since
//! that is what the firmware interface says. For a fuzzer it is a wall. Every
//! mutation of a table that passes lands one that does not, so the corpus
//! cannot accumulate structure in the body: guidance keeps rediscovering the
//! door and never gets down the corridor.
//!
//! That is not a hypothesis. A first run of this target plateaued at 23 corpus
//! units within seconds, and only nine of them summed to zero — the rest were
//! inputs whose only distinction was a new way of being rejected. Nothing past
//! the header was being explored at all.
//!
//! So each input is parsed twice, and the pair is the point:
//!
//! * **as it arrived**, which is the only way the gate itself gets tested — a
//!   short buffer, a wrong signature, a length disagreeing with the buffer, a
//!   checksum that does not add up. Those paths exist to reject, and only an
//!   input that fails them proves they do.
//! * **repaired**, with the signature, the length field and the checksum byte
//!   made consistent, so the remaining bytes are read as the table body the
//!   fuzzer is otherwise locked out of. This is where the parsing that matters
//!   happens: a structure length of zero, a remapping-structure header that
//!   reaches past the table, arithmetic on a length firmware chose.
//!
//! Repair widens what is tested rather than narrowing it. Firmware that writes
//! a correct checksum over a malicious body is the realistic threat anyway —
//! the checksum is an integrity check against a truncated table, and an
//! attacker computes it as easily as a vendor's build script does.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. `None` is a perfectly good answer and the
//! common one on the unrepaired path — most byte strings are not a `DMAR`.
//!
//! Nothing here bounds the walk, deliberately. The loop that could fail to
//! terminate is inside `parse_dmar`, over the remapping structures, where a
//! length of zero is the loop increment; it would hang before ever returning,
//! and a bound in the harness could not interrupt it. `units()` and
//! `regions()` walk fixed arrays of eight and cannot run long. A hang is
//! therefore libFuzzer's `-timeout` to report, and the harness should not
//! pretend to catch what it cannot reach.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run dmar_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_arch::acpi::{Dmar, parse_dmar};

/// The checksum byte's offset in an ACPI table header.
const CHECKSUM: usize = 9;

/// The shortest buffer `parse_dmar` will look past: the 36-byte ACPI header,
/// the host address width byte, the flags byte, and ten reserved bytes.
///
/// Duplicated from the parser rather than exported by it. A harness that
/// imported the constant would follow the parser if it ever changed, and the
/// point of a fuzz target is to be a second opinion about the shape of the
/// input, not an echo of the first.
const DMAR_HEADER: usize = 48;

fuzz_target!(|data: &[u8]| {
    walk(parse_dmar(data));

    // Below the parser's own floor there is no header to repair, and the
    // unrepaired call above has already tested what happens to a short buffer.
    if data.len() < DMAR_HEADER || u32::try_from(data.len()).is_err() {
        return;
    }

    let mut table = data.to_vec();
    table[0..4].copy_from_slice(b"DMAR");
    // The length field, made to agree with the buffer. Left to the fuzzer it
    // is four bytes that must equal a number the fuzzer cannot see, and the
    // body is unreachable until they do.
    let length = u32::try_from(table.len()).unwrap_or(u32::MAX);
    table[4..8].copy_from_slice(&length.to_le_bytes());
    // Zeroed first so the byte does not count towards the sum it corrects.
    table[CHECKSUM] = 0;
    let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    table[CHECKSUM] = 0u8.wrapping_sub(sum);

    walk(parse_dmar(&table));
});

/// Reads everything a caller would read.
///
/// Enumerating the units is part of the target rather than a separate one: a
/// table is only half-parsed until something walks it, and what the kernel
/// goes on to *use* is a register base out of this iterator.
fn walk(dmar: Option<Dmar>) {
    let Some(dmar) = dmar else {
        return;
    };

    for unit in dmar.units() {
        core::hint::black_box(&unit);
    }
    for region in dmar.regions() {
        core::hint::black_box(&region);
    }
    core::hint::black_box((
        dmar.unit_count(),
        dmar.region_count(),
        dmar.host_address_width,
        dmar.interrupt_remapping,
        dmar.units_seen,
        dmar.regions_seen,
        dmar.truncated,
    ));
}
