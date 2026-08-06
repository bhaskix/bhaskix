// SPDX-License-Identifier: Apache-2.0
//! The filesystem service, and the archive it reads.
//!
//! Three things that belong together and, until RFC 0013 step 3, were three
//! modules of the kernel: a `ustar` parser that trusts nothing, a `vfs` that
//! resolves names in it, and the service that answers `fs::` methods over IPC.
//!
//! Nothing here can name a kernel type. The parser never could — it is
//! arithmetic over a byte slice — and the service can no longer, which was the
//! whole of step 3's work. The kernel still uses `vfs` directly for its own
//! shell, which is allowed: the arrow points from the kernel to the service
//! crate and never back.
#![no_std]
// The panic bans exist to stop a fallible operation taking down the service,
// and a test that cannot panic cannot fail. Stated here because the workspace
// lint table cannot express a cfg-conditional allow — and stated *now* because
// until `make test-host` learned to say `--workspace`, this crate's tests were
// neither run nor linted, so nothing had ever asked.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

// For the tests only: the archive fixtures build tar images at runtime, which
// wants a growable buffer. Nothing outside `#[cfg(test)]` allocates -- the
// parser reads a borrowed slice and the service holds fixed-size sessions,
// which is what lets this crate run in a domain with no heap under it.
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod ustar;
pub mod vfs;

mod service;

pub use service::{Bulk, Filesystem, MAX_PATH, MAX_SESSIONS, Session};
