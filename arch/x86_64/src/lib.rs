// SPDX-License-Identifier: Apache-2.0
//! x86_64 architecture support for Bhaskix.
//!
//! This crate is the only place x86-specific instructions appear. Portable
//! code programs against the interfaces re-exported here rather than emitting
//! `asm!` of its own; see `docs/architecture.md` §7 for the `Arch` trait
//! boundary this will grow into.
//!
//! It depends on nothing. That is deliberate and is enforced in CI: the
//! dependency direction is `arch -> (nothing)`, so `arch` can be built and
//! reasoned about in isolation.

#![cfg_attr(not(test), no_std)]

pub mod cell;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod port;
pub mod serial;
pub mod trap;

pub use serial::SerialPort;
pub use trap::TrapFrame;
