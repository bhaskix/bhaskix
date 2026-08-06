// SPDX-License-Identifier: Apache-2.0
//! Two registers at the same bytes. This must not compile.
//!
//! The four-byte register at 0x00 runs to 0x04, and the two-byte one at 0x02
//! is inside it. A block whose fields overlap is a block where writing one
//! silently changes another, and the offsets are exactly the sort of thing
//! that gets copied from a specification by hand.
#![no_std]

bhaskix_device::register_block! {
    /// Wrong on purpose.
    pub struct Overlapping(0x20) {
        0x00 => wide: u32,
        0x02 => inside_it: u16,
    }
}
