// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the `TPM2_PCR_Read` response parser -- RFC 0089
//! step 5b.
//!
//! The response is bytes **a device wrote** into the CRB data buffer, and a
//! TPM is hardware this machine did not build: `coding-style.md` §8 makes a
//! target mandatory before the parser merges.
//!
//! # What counts as a failure
//!
//! A panic, an abort or a hang -- and one property beyond not crashing: **an
//! accepted response gives exactly a digest of the bank's size**, for the PCR
//! the first byte of the input chose. What the service answers is that digest,
//! in four reply words, so its length is the one thing the caller relies on.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run tpm_response -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_tpm::command::{SHA256_DIGEST, TPM_ALG_SHA256, parse_pcr_read_response};

fuzz_target!(|data: &[u8]| {
    let Some((&first, response)) = data.split_first() else {
        return;
    };
    let pcr = first % 24;
    if let Ok(digest) = parse_pcr_read_response(response, TPM_ALG_SHA256, pcr, SHA256_DIGEST) {
        assert_eq!(digest.len(), SHA256_DIGEST);
    }
});
