// SPDX-License-Identifier: Apache-2.0
//! Memory management.
//!
//! At M2 this is only the boot-time bump allocator. The buddy allocator, the
//! slab, address spaces, and demand paging arrive in M3; see `docs/memory.md`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod bump;

pub use bump::{BumpAllocator, FRAME_SIZE};
