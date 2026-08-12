// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the Ethernet II framing parser.
//!
//! The first fourteen bytes of every packet this system will ever receive. It
//! is the smallest parser in `bhaskix-net` and the one with the most reachable
//! call sites, because nothing gets past it without going through it.
//!
//! # Why a network parser is a different proposition from the others here
//!
//! `elf_parse`, `ustar_parse` and `dmar_parse` all read a *medium* — a file, an
//! archive, a firmware table — supplied by whoever can write the boot device.
//! These bytes arrive from anyone who can reach the wire, continuously, at line
//! rate. The parser is the same size; the number of parties who can drive it is
//! not.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: random bytes are not a
//! frame, and refusing them is the correct answer. What must never happen is a
//! slice out of bounds, or a payload whose length exceeds the input it came
//! from — which is asserted here rather than left to a reader, because it is
//! the specific way this parser could be wrong while still returning `Ok`.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run eth_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{addr::MacAddr, eth::EthFrame};

fuzz_target!(|data: &[u8]| {
    const MINE: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    if let Ok(frame) = EthFrame::parse(data) {
        // The receive filter is part of the parser's contract: every caller
        // applies it, so a campaign that never calls it covers less than it
        // appears to.
        let _ = frame.addressed_to(MINE);
        let _ = frame.addressed_to(MacAddr::BROADCAST);

        // A returned payload longer than the input would mean the parser
        // fabricated bytes. It cannot happen through a slice, and asserting it
        // is what makes that still true after the next refactor.
        assert!(frame.payload.len() <= data.len());
    }
});
