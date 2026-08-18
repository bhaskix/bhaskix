// SPDX-License-Identifier: Apache-2.0
//! The package format: a program plus the authority it asks for, readable.
//!
//! [RFC 0030](../../docs/rfc/0030-packages.md) step 1. Three modules, three
//! refusals-first parsers:
//!
//! - [`manifest`] — the line grammar that states a package's name, its
//!   programs, their capability requests, and the digest of every payload.
//! - [`package`] — the `.bpk` walk: manifest first, every member proven
//!   against it or the whole refused.
//! - [`sha256`] — content identity as arithmetic, honest about being
//!   corruption detection until Phase 3 signs the manifest.
//!
//! The archive subset is [`bhaskix_ustar`]'s — the initrd's own, one parser
//! for every consumer. Nothing here allocates, nothing is `unsafe`
//! (`forbid`, and the budget is written as zero), and nothing executes:
//! this crate decides whether bytes are a package, and what its manifest
//! says. Acting on that — copying, granting, starting — belongs to whoever
//! holds the authority to act.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

pub mod manifest;
pub mod package;
pub mod sha256;
