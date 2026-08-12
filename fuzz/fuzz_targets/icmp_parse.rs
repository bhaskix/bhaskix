// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the ICMP echo parser.
//!
//! The smallest parser in `bhaskix-net` and the one with the most direct route
//! to a stranger's bytes: an echo request needs no connection, no port and no
//! prior exchange. Anyone who can reach the address can make this code run.
//!
//! # The checksum, and why this target repairs it
//!
//! `docs/coding-style.md` §8 records what `DMAR` taught this project: a parser
//! behind a whole-input checksum is unreachable to a fuzzer that does not
//! repair it, and a target that does not say so reports a clean campaign over
//! the doorway. ICMP's checksum covers the **entire message**, payload
//! included, so every mutation invalidates it — which would leave everything
//! past the first check untouched by the whole campaign.
//!
//! So this parses twice: once as given, exercising the checksum path itself,
//! and once repaired, so the type and code checks behind it are reachable.
//!
//! # The round trip is the second half of the target
//!
//! An echo reply must return the request's payload *exactly*, so a writer that
//! truncated or padded would still produce something that parses. Rebuilding
//! what parsed and requiring the two to agree is what catches that, and it
//! reaches the writer, which host tests only ever drive with well-formed input.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run icmp_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{checksum, icmp};

/// Recomputes the checksum in place, so the fields behind it are reachable.
fn repair(bytes: &mut [u8]) {
    if bytes.len() < icmp::HEADER {
        return;
    }
    bytes[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum(&[bytes]);
    bytes[2..4].copy_from_slice(&sum.to_be_bytes());
}

fuzz_target!(|data: &[u8]| {
    // As given: the checksum check itself, and every refusal in front of it.
    if let Ok(parsed) = icmp::Echo::parse(data) {
        assert!(parsed.payload.len() + icmp::HEADER <= data.len());
    }

    // Repaired: everything behind the checksum.
    let mut bytes = [0u8; 2048];
    let length = data.len().min(bytes.len());
    bytes[..length].copy_from_slice(&data[..length]);
    repair(&mut bytes[..length]);

    let Ok(parsed) = icmp::Echo::parse(&bytes[..length]) else {
        return;
    };
    assert!(parsed.payload.len() + icmp::HEADER <= length);

    // Round trip. What parsed must rebuild, and the rebuilt message must parse
    // again to the same fields -- an echo whose payload came back different is
    // an echo that answered a different question.
    let mut out = [0u8; 2048];
    if let Ok(written) = icmp::write(
        &mut out,
        parsed.is_reply,
        parsed.identifier,
        parsed.sequence,
        parsed.payload,
    ) {
        let again = icmp::Echo::parse(&out[..written]).expect("what this code wrote must parse");
        assert_eq!(again.payload, parsed.payload);
        assert_eq!(again.identifier, parsed.identifier);
        assert_eq!(again.sequence, parsed.sequence);
        assert_eq!(again.is_reply, parsed.is_reply);
    }
});
