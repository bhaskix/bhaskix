// SPDX-License-Identifier: Apache-2.0
//! Memory management.
//!
//! At M3 this provides the boot-time bump allocator and the buddy-based
//! physical memory manager. Address spaces, the slab allocator, and demand
//! paging follow; see `docs/memory.md`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// docs/coding-style.md §4 specifies: those exist to stop a fallible operation
// from taking down the nucleus, and a test that cannot panic cannot fail.
// The workspace lint table cannot express a cfg-conditional allow, so it is
// stated here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod bump;
pub mod pmm;

pub use bump::{BumpAllocator, FRAME_SIZE};
pub use pmm::{Frame, Pmm, Zone};
