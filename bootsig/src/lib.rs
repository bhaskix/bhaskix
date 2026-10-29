// SPDX-License-Identifier: Apache-2.0
//! The boot set's signature: what [RFC 0091](../../docs/rfc/0091-a-boot-its-owner-signed.md)'s
//! loader checks before it parses a kernel.
//!
//! Two modules:
//!
//! - [`slh_dsa`]: SLH-DSA-SHA2-128s verification (FIPS 205), one parameter
//!   set, checked against NIST's ACVP vectors.
//! - [`statement`]: the 128-byte statement `boot.sig` carries, and [`check`],
//!   which says which check a boot set failed.
//!
//! Its only dependency is [`bhaskix_sha256`], which is the reason SLH-DSA was
//! chosen: verification needs nothing the tree did not already have. Nothing
//! here allocates, nothing is `unsafe` (`forbid`, and the budget is zero),
//! and nothing secret enters it.
//!
//! **What step 1 cannot test yet**: [`check`] *accepting* a boot set. That
//! needs a signature over a statement, and the signer is step 2's
//! (`tools/bootsign`). Until then the accepting path of the signature itself
//! is proven by the ACVP vectors through [`slh_dsa::verify`], and every
//! refusal of [`check`] has its own test.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

pub mod slh_dsa;
pub mod statement;

pub use statement::check;
