// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the Linux personality's address parsers.
//!
//! RFC 0005 Tier 2, and RFC 0031's reason for insisting the personality is
//! the largest untrusted-input parser this project will ever have. A
//! `sockaddr` arrives from a **hosted process**: bytes it wrote, at a length
//! it chose, in a structure whose two length variants differ by twelve bytes
//! and whose port is network-endian inside a host-endian header. The RFC
//! makes a fuzz target mandatory before a tier merges, and this is Tier 2's.
//!
//! The `epoll_event` decoder rides along because it is the same hazard in a
//! smaller shape: a twelve-byte packed structure a caller supplies, whose
//! eight-byte word is unaligned.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal — random bytes are not a
//! `sockaddr`, and answering `EINVAL` or `EAFNOSUPPORT` is the correct
//! result. What must never happen is a read past the slice, arithmetic that
//! wraps on a caller-supplied length, or an *accepted* address whose
//! round trip does not reproduce it.
//!
//! Two properties are asserted rather than merely exercised:
//!
//! 1. **An accepted address fits in the length the caller claimed.** A parse
//!    that succeeded on fewer bytes than the family needs is the bug this
//!    whole file exists to catch, and it would be invisible otherwise.
//! 2. **Writing an accepted address back and parsing it again is the same
//!    address.** A one-way parser can be wrong in a way no single call
//!    reveals; a round trip makes the byte order and the field offsets
//!    check each other.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run linux_sockaddr -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_personality::{event, socket};

fuzz_target!(|data: &[u8]| {
    // The claimed length is the first byte, so the fuzzer can reach the
    // disagreement between "what the caller said" and "what the caller gave"
    // without having to discover a whole u64 by chance. That disagreement is
    // the interesting half of this parser.
    let (claimed, bytes) = match data.split_first() {
        Some((first, rest)) => (usize::from(*first), rest),
        None => (0, data),
    };

    if let Ok(endpoint) = socket::parse_endpoint(bytes, claimed) {
        // Property 1: never accepted on fewer bytes than the family needs.
        assert!(endpoint.bytes() <= claimed);
        assert!(claimed <= bytes.len());

        // Property 2: the round trip reproduces it exactly.
        let mut out = [0u8; socket::SOCKADDR_IN6_BYTES];
        let written = socket::write_endpoint(&mut out, &endpoint).expect("a full buffer fits");
        assert_eq!(written, endpoint.bytes());
        assert_eq!(
            socket::parse_endpoint(&out, written),
            Ok(endpoint),
            "an address this parser accepted did not survive being written back"
        );

        // A short output buffer must truncate rather than refuse or overrun,
        // and must still answer the *whole* length — which is how a caller
        // learns it was truncated.
        for room in 2..written {
            let mut small = [0u8; socket::SOCKADDR_IN6_BYTES];
            assert_eq!(
                socket::write_endpoint(&mut small[..room], &endpoint),
                Ok(written)
            );
        }
    }

    // The same bytes as a socket() argument triple, so the refusals get
    // exercised on values nobody would think to write down.
    if bytes.len() >= 24 {
        let word = |at: usize| {
            let mut eight = [0u8; 8];
            eight.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(eight)
        };
        let _ = socket::plan_socket(word(0), word(8), word(16));
    }

    // And as an `epoll_event`: twelve packed bytes with an unaligned word.
    if let Ok((interest, data_word)) = event::parse_event(bytes) {
        let mut set = event::Set::new();
        // The descriptor comes from the input too, so negative and
        // out-of-range numbers are reached rather than assumed unreachable.
        let descriptor = i32::from_le_bytes([
            bytes.first().copied().unwrap_or(0),
            bytes.get(1).copied().unwrap_or(0),
            0,
            0,
        ]);
        for operation in [event::control::ADD, event::control::MOD, event::control::DEL] {
            let _ = set.control(operation, -1, descriptor, interest, data_word);
        }
        let mut out = [0u8; event::EVENT_BYTES * 4];
        if let Ok(reported) = set.report(&mut out, 4, |_| interest) {
            assert!(reported <= 4);
            assert!(reported <= set.len());
        }
        set.forget(descriptor);
    }
});
