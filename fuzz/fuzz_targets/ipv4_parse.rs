// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the IPv4 header parser and fragment reassembly.
//!
//! The most valuable target in `bhaskix-net`, for two reasons.
//!
//! **Three lengths that must agree.** The internet header length, the total
//! length, and the bytes actually supplied. Every IPv4 parser bug of
//! consequence is a failure to check one of them against the others, and they
//! interact — a header length valid against the buffer can still be invalid
//! against the total length inside it.
//!
//! **Reassembly is stateful, and the state is chosen by a remote party.** The
//! table holds bytes at offsets a sender picks, for a duration a sender's
//! silence decides, keyed on fields a sender controls. That is the classic
//! resource-exhaustion primitive and it has an older sibling: overlapping
//! fragments, where the same offset is claimed twice with different bytes and
//! the reassembled datagram depends on which the stack believed.
//!
//! # The checksum, and the lesson `DMAR` taught this project
//!
//! `docs/coding-style.md` §8 records it: a parser guarded by a whole-input
//! checksum is unreachable to a fuzzer that does not repair it, and a target
//! that does not say so reports a clean campaign over the doorway. The DMAR
//! target plateaued at 23 corpus units for exactly this reason.
//!
//! An IPv4 header checksum covers only the header, not the datagram, but the
//! effect is the same: mutate any of twenty bytes and the checksum fails, so
//! nothing behind it is ever reached. **This target parses twice** — once with
//! the input as given, so the checksum check itself is exercised, and once with
//! the checksum repaired, so every length check behind it is reachable.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run ipv4_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    checksum,
    ipv4::{self, Ipv4Header, Reassembly},
};

/// Recomputes the header checksum in place, so the fields behind it are
/// reachable. See the module header.
fn repair(bytes: &mut [u8]) {
    if bytes.len() < ipv4::HEADER {
        return;
    }
    let words = usize::from(bytes[0] & 0x0f) * 4;
    let length = if (ipv4::HEADER..=bytes.len()).contains(&words) {
        words
    } else {
        ipv4::HEADER
    };
    bytes[10..12].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&bytes[..length]]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
}

fuzz_target!(|data: &[u8]| {
    const ENTRIES: usize = 4;
    const MAX: usize = 2048;

    /// The parser's own contract, asserted rather than assumed: a header that
    /// parses must have agreed with itself, and its payload must be exactly the
    /// span the two lengths describe.
    fn check(header: &Ipv4Header, payload: &[u8], input: usize) {
        assert!(header.header_length >= ipv4::HEADER);
        assert!(header.header_length <= header.total_length);
        assert!(header.total_length <= input);
        assert_eq!(payload.len(), header.total_length - header.header_length);
    }

    // As given, so the checksum check is exercised.
    if let Ok((header, payload)) = Ipv4Header::parse(data) {
        check(&header, payload, data.len());
    }

    // Repaired, so everything behind the checksum is reachable, and driven into
    // a reassembly table across a sequence of fragments.
    let mut table = Reassembly::<ENTRIES, MAX>::new(1_000_000_000);
    for (step, chunk) in data.chunks(64).enumerate() {
        let mut bytes = [0u8; 64];
        let Some(room) = bytes.get_mut(..chunk.len()) else {
            continue;
        };
        room.copy_from_slice(chunk);
        repair(&mut bytes[..chunk.len()]);

        let Ok((header, payload)) = Ipv4Header::parse(&bytes[..chunk.len()]) else {
            continue;
        };
        check(&header, payload, chunk.len());

        let now = step as u64 * 100_000_000;
        if let Ok(Some(index)) = table.offer(&header, payload, now) {
            let assembled = table.assembled(index).expect("complete implies assembled");
            assert!(assembled.len() <= MAX);
            table.release(index);
        }
        // The bound the fixed table exists to provide. A remote party choosing
        // identifications must not be able to make this grow.
        assert!(table.in_flight() <= ENTRIES);
    }
    let _ = table.expire(u64::MAX);
    assert_eq!(table.in_flight(), 0);
});
