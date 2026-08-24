// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the `IDENTIFY DEVICE` parser.
//!
//! [RFC 0046](../../docs/rfc/0046-a-driver-for-hardware-that-exists.md)'s
//! security section makes this mandatory, and the reason is easy to miss:
//! `IDENTIFY` looks like configuration rather than input. It is 512 bytes **a
//! device wrote**, and a sector count taken out of it sizes later transfers by
//! a bus master. Firmware is buggy and a disk on a shared bus is not a trusted
//! peer.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal — random bytes are not a
//! disk, and `NotADisk` is the correct answer to nearly all of them.
//!
//! Two properties are asserted beyond "does not crash":
//!
//! 1. **An accepted answer can be multiplied out without overflowing.** The
//!    parser's job is to make `sectors * sector_bytes` safe for everything
//!    downstream, and that is checked here rather than trusted.
//! 2. **An accepted sector size is a power of two and at least 512.** A
//!    transfer sized by anything else is a transfer whose length arithmetic
//!    the rest of the driver gets to be wrong about.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run ahci_identify -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_ahci::{IDENTIFY_BYTES, read_identity};

fuzz_target!(|data: &[u8]| {
    // Short inputs must be refused rather than read past, and that is cheap to
    // reach by chance only if it is asked for.
    if data.len() < IDENTIFY_BYTES {
        let _ = read_identity(data);
        return;
    }
    let Ok(identity) = read_identity(&data[..IDENTIFY_BYTES]) else {
        return;
    };

    assert!(identity.sectors > 0, "an accepted disk with no sectors");
    assert!(
        identity.sector_bytes >= 512 && identity.sector_bytes.is_power_of_two(),
        "sector size {} would break every length calculation downstream",
        identity.sector_bytes
    );
    assert!(
        identity
            .sectors
            .checked_mul(u64::from(identity.sector_bytes))
            .is_some(),
        "an accepted disk whose size cannot be multiplied out"
    );
});
