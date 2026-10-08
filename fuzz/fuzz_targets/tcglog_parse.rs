// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the TPM event-log parser -- RFC 0089.
//!
//! The log is bytes **firmware wrote**, copied by the loader and read by the
//! system that will one day decide on them; whoever can replace the firmware
//! or the loader chooses every length in it. `coding-style.md` §8 makes a
//! target mandatory before the parser merges.
//!
//! # What counts as a failure
//!
//! A panic, an abort or a hang -- and four properties beyond not crashing:
//!
//! 1. **An accepted header declares a sane set**: one to `MAX_ALGORITHMS`
//!    algorithms, each named once, each digest one to `MAX_DIGEST` bytes.
//! 2. **Every accepted event carries exactly the declared banks**: a digest of
//!    the declared size for each declared algorithm, which a replay relies on.
//! 3. **`event2_len` and the walk agree**, event by event, from a start this
//!    target computes itself rather than borrows from the parser.
//! 4. **A walk that ends without an error has consumed every byte**: no event
//!    may be skipped silently.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run tcglog_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_tcglog::log::{Log, MAX_ALGORITHMS, MAX_DIGEST, event2_len};

fuzz_target!(|data: &[u8]| {
    let Ok(log) = Log::parse(data) else {
        return;
    };
    let algorithms = log.spec().algorithms();
    assert!(!algorithms.is_empty() && algorithms.len() <= MAX_ALGORITHMS);
    for (index, &(id, size)) in algorithms.iter().enumerate() {
        assert!(size > 0 && size <= MAX_DIGEST);
        assert!(algorithms[..index].iter().all(|&(other, _)| other != id));
    }
    // Where the events start, computed here: the header event's data begins at
    // 32 and runs for the length at 28.
    let size = u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize;
    let mut rest = &data[32 + size..];
    for event in log.events() {
        let Ok(event) = event else {
            assert!(event2_len(rest, log.spec()).is_err());
            return;
        };
        for &(id, size) in algorithms {
            assert_eq!(event.digest(id).map(<[u8]>::len), Some(usize::from(size)));
        }
        let len = event2_len(rest, log.spec()).expect("the walk accepted this event");
        rest = &rest[len..];
    }
    assert!(
        rest.is_empty(),
        "the walk ended before the bytes did, without an error"
    );
});
