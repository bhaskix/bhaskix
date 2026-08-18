// SPDX-License-Identifier: Apache-2.0
//! The client side of the network — RFC 0027.
//!
//! A `no_std` library for ring 3 programs that already hold network
//! capabilities. Nothing here confers authority: every function takes the
//! slots and addresses as arguments, and a program that was not granted the
//! network cannot name it through this crate any more than without it. What
//! the crate holds is the *lessons* — the exchange shapes, the refusal
//! handling, the wait discipline — that three programs used to carry as
//! hand-rolled copies with local variations.
//!
//! No allocation, no global state, no descriptors, no POSIX: the native API
//! is capabilities (RFC 0008's answer to A4), and this crate is its
//! ergonomic shore, not a shim over it.

// Nothing that ships sees `std`: the crate is `no_std` in every build that
// is not the test harness.
#![cfg_attr(not(test), no_std)]

pub mod call;
pub mod ring;
pub mod tcp;
pub mod time;
pub mod udp;
pub mod udp6;
pub mod wait;
