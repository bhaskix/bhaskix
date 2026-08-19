// SPDX-License-Identifier: Apache-2.0
//! The Linux personality, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md): the Linux
//! `x86_64` ABI is a *personality* — a translation layer over the
//! capabilities a domain already holds — and never the native interface.
//! This crate is the half of it that needs no machine: what a process's
//! initial state is, and (as tiers land) what each system call's arguments
//! mean, as pure functions over byte buffers.
//!
//! Nothing here holds authority, allocates, or is `unsafe` — `forbid`, with
//! the budget written as zero. The kernel calls in; a host test checks the
//! bytes. That split is what makes the auxv builder testable at all, and the
//! RFC's testing plan names it as the preferred shape.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

pub mod event;
pub mod file;
pub mod memory;
pub mod signal;
pub mod socket;
pub mod stack;
pub mod thread;
