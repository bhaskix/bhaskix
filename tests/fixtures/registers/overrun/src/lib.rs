// SPDX-License-Identifier: Apache-2.0
//! A register past the end of its block. This must not compile.
//!
//! The block is sixteen bytes and the register at 0x0c is eight, so it runs
//! four bytes past the end — into whatever the device puts next, which on a
//! virtio device is another structure entirely.
#![no_std]

bhaskix_device::register_block! {
    /// Wrong on purpose.
    pub struct Overrunning(0x10) {
        0x0c => past_the_end: u64,
    }
}
