// SPDX-License-Identifier: Apache-2.0
//! Panic reporting.
//!
//! The `#[panic_handler]` itself lives in the binary crate (`boot/shim`),
//! because a `no_std` binary may define exactly one and putting it here would
//! stop this crate from being unit-tested on the host. This module holds the
//! part that matters: what gets printed.
//!
//! A panic in the nucleus is a denial of service and is treated as a bug of
//! the same severity as whatever caused it (`docs/coding-style.md` §4). The
//! job of this code is therefore to make the next person's debugging session
//! as short as possible.
//!
//! # Constraints
//!
//! This runs after something has already gone wrong, so it assumes as little
//! as possible: no allocation, no locks it does not already hold uncontended,
//! no interrupts, no return. It prints and halts.

use core::panic::PanicInfo;

use bhaskix_arch::cpu;

use crate::println;

/// Prints a panic report and stops the CPU.
///
/// Never returns, and never reboots. A machine that reboots on panic loses the
/// message, and the operator sees only a boot loop with no cause — which is
/// how a five-minute bug becomes a five-hour one.
pub fn report(info: &PanicInfo<'_>) -> ! {
    println!();
    println!("==================================================================");
    println!("  KERNEL PANIC");
    println!("==================================================================");

    match info.location() {
        Some(location) => {
            println!(
                "  at {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }
        None => println!("  at (location unavailable)"),
    }

    println!("  {}", info.message());

    println!("------------------------------------------------------------------");
    println!("  This is a bug. Please report it with everything above:");
    println!("  https://github.com/bhaskix/bhaskix/issues");
    println!();
    println!("  A stack backtrace is not available yet -- it needs the frame");
    println!("  walker that arrives with the exception handlers in M2.");
    println!("==================================================================");

    cpu::halt_forever()
}
