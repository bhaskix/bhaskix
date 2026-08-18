// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the whole `.bpk` walk.
//!
//! RFC 0030: `verify` is the single gate between "bytes an operator was
//! handed" and "a package an installer copies from" — the archive walk, the
//! manifest parse, the digest and length checks and the unclaimed-member
//! refusal, composed. Composition is why it gets its own target beside
//! `ustar_parse` and `pkg_manifest`: each layer can hold alone and the seam
//! between them still be wrong, and the seam is where a member's *name*
//! meets a manifest's *path*.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: almost every input is
//! refused, each with a typed reason. On the rare accepted input, every
//! payload the manifest names is fetched through `data()` and its length
//! re-checked against the file line — an acceptance whose promises then fail
//! is exactly the composed bug this target exists to catch.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run pkg_package -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_pkg::package;

fuzz_target!(|data: &[u8]| {
    if let Ok(verified) = package::verify(data) {
        for file in verified.manifest().files() {
            // Everything the manifest names was proven present, with this
            // length. Hold verify to its own promise.
            let payload = verified.data(file.path).expect("verified file present");
            assert_eq!(payload.len() as u64, file.length);
        }
    }
});
