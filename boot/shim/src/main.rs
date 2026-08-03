// SPDX-License-Identifier: Apache-2.0
//! The Bhaskix kernel binary.
//!
//! This crate owns the ELF entry point and the panic handler, and does exactly
//! three things: check that the bootloader honoured the protocol we asked for,
//! translate its data into [`bhaskix_boot::Handoff`], and call the nucleus.
//!
//! It is the top of the dependency graph rather than the bottom. That is what
//! lets `kernel/` be free of any mention of a bootloader: the shim depends on
//! the kernel, not the other way round (`docs/architecture.md` §1).

#![no_std]
#![no_main]

mod limine;

use core::panic::PanicInfo;

use bhaskix_arch::cpu;
use bhaskix_arch::serial::COM1;
use bhaskix_kernel::{console, kernel_main, println};

/// ELF entry point.
///
/// Called by the bootloader in 64-bit long mode with interrupts disabled, a
/// valid stack, and the kernel mapped in the higher half.
#[unsafe(no_mangle)]
pub extern "C" fn bhaskix_start() -> ! {
    if !limine::base_revision_supported() {
        // Bring up serial by hand so this is diagnosable. Nothing else is
        // trustworthy at this point — if the base revision is wrong, the
        // memory map and HHDM may mean something other than what we expect,
        // so we do not touch them.
        console::init_serial(COM1);
        println!();
        println!("  FATAL: the bootloader does not support Limine base revision 3.");
        println!("  Refusing to continue: the memory map and higher-half direct map");
        println!("  would have different semantics than this kernel was built for.");
        cpu::halt_forever();
    }

    // SAFETY: this is the entry point. It runs exactly once, on the bootstrap
    // CPU, with interrupts disabled and no other CPU started — which is
    // precisely what `collect_handoff` requires.
    let handoff = unsafe { limine::collect_handoff() };

    kernel_main(&handoff)
}

/// Kernel panic handler.
///
/// Delegates to the nucleus so that the reporting logic lives with the rest of
/// the kernel; a `no_std` binary may define only one of these, and defining it
/// here keeps `bhaskix-kernel` unit-testable on the host.
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    bhaskix_kernel::panic::report(info)
}
