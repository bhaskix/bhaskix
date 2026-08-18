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

pub mod acpi;
pub mod apic;
pub mod cell;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod ioapic;
pub mod mp;
pub mod msr;
pub mod paging;
pub mod pci;
pub mod percpu;
pub mod pic;
pub mod port;
pub mod serial;
pub mod syscall;
pub mod trap;
pub mod tsc;
pub mod uaccess;
pub mod vtd;

pub use context::Context;
pub use serial::SerialPort;
pub use trap::TrapFrame;
