// SPDX-License-Identifier: Apache-2.0
//! The installable greeting.
//!
//! [RFC 0030](../../../docs/rfc/0030-packages.md) step 3's payload: this
//! program exists to be the first thing installed onto the machine as a
//! package rather than baked into the image — and, at step 4, the first
//! thing started with grants derived from a manifest instead of wired by
//! hand. It holds one capability, a console, because that is all its
//! manifest asks; everything it prints is proof the grant chain worked.

#![no_std]
#![no_main]

use bhaskix_abi::{Chunk, console, syscall};

/// The console this program greets through — its only capability.
const CONSOLE: u64 = 0;

/// What it says. Proof of the whole chain: packaged, verified, installed,
/// granted, started.
const GREETING: &[u8] = b"namaste from an installed package\n";

/// One syscall, RFC 0008's register convention.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> u64 {
    let status: u64;
    // SAFETY: the system call convention from RFC 0008; every output
    // register is listed.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") args[0] => _,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    status
}

/// The entry point. `hertz` arrives as every packaged program's manifest
/// declares (`entry hertz`); this one has nothing to time and ignores it.
#[unsafe(no_mangle)]
extern "C" fn hello_main(_hertz: u64) -> ! {
    let mut rest = GREETING;
    while !rest.is_empty() {
        let (chunk, tail) = Chunk::take(rest);
        let _ = call(syscall::CALL, CONSOLE, console::WRITE, chunk.pack(0));
        rest = tail;
    }
    let _ = call(bhaskix_abi::syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats carrying on half-built.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call hello_main
    ud2
"#
);
