// SPDX-License-Identifier: Apache-2.0
//! Memory management.
//!
//! At M3 this provides the boot-time bump allocator and the buddy-based
//! physical memory manager. Address spaces, the slab allocator, and demand
//! paging follow; see `docs/memory.md`.

#![cfg_attr(not(test), no_std)]
// `deny` rather than `forbid`, so the slab allocator can opt back in.
// Everything else in this crate is pure arithmetic over the memory map and the
// frame database and must stay unsafe-free; the slab has to write free-list
// links into the objects it manages, which no safe abstraction can express.
#![deny(unsafe_code)]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans and from the
// SAFETY-comment requirement, as docs/coding-style.md §3 and §4 specify. The
// panic bans exist to stop a fallible operation taking down the nucleus, and a
// test that cannot panic cannot fail; the `unsafe` budget tracks the auditable
// surface of the kernel as deployed, and test code does not ship. The workspace
// lint table cannot express a cfg-conditional allow, so it is stated here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

pub mod bump;
pub mod pmm;

#[allow(unsafe_code)]
pub mod slab;

pub use bump::{BumpAllocator, FRAME_SIZE};
pub use pmm::{Frame, Pmm, Zone};
pub use slab::{Heap, HeapError};
