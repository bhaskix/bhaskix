// SPDX-License-Identifier: Apache-2.0
//! The console service, in a domain of its own.
//!
//! No console code lives here. All of it is in `bhaskix-service-console`,
//! which is the same crate the kernel compiles into itself when
//! `services.toml` says `nucleus`: the same filter, the same chunk packing,
//! the same draining read. What this file supplies is a **context** built out
//! of system calls, and `serve::<Console>` instead of `run::<Console>`.
//!
//! # What it holds, and what that is worth
//!
//! Two capabilities: the endpoint it answers on, and a `Console`. The console
//! capability permits putting a character and taking a byte, and nothing else
//! — so a console service that was talked into doing something it should not
//! can still only put characters and take bytes. The same service in the
//! nucleus could do anything the kernel can, which is the difference this
//! placement is for and the reason the capability is narrow rather than "the
//! console device".
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall};
use bhaskix_service_console::{Console, Ports};

/// The slot the kernel puts this domain's endpoint capability in.
const ENDPOINT: u64 = 0;

/// The slot the kernel puts the console capability in.
const CONSOLE: u64 = 1;

/// There is nothing to unwind, and the way to report is the thing that failed.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A console service that
    // panicked cannot print why, so stopping visibly beats continuing.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, arg0: u64) -> (u64, u64) {
    let status: u64;
    let mut value = arg0;
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side.
    //
    // Every argument register is declared as an *output* as well, because the
    // kernel writes the whole frame back on the way out -- so `rdi`, `rsi`,
    // `rdx`, `r10`, `r8` and `r9` all come back changed whether this call uses
    // them or not. Declaring them as inputs was a lie to the compiler, and it
    // was believed: it kept a live value in `r8` across a `syscall`, and the
    // first thing this program did with the kernel's leftovers in it was
    // dereference one. `rcx` and `r11` are destroyed by the instruction
    // itself.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            lateout("r10") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// The same call with a second argument, for `PUT_RUN` — RFC 0050.
///
/// `call` above carries one, which was every method this service used until a
/// run of bytes needed an address *and* a length. Kept separate rather than
/// widening the one above, because every other call site would then pass a zero
/// that means nothing.
fn call2(kind: u64, capability: u64, method: u64, arg0: u64, arg1: u64) -> (u64, u64) {
    let status: u64;
    let mut value = arg0;
    // SAFETY: as `call` above, and for the same reasons -- every argument
    // register is an output because the kernel writes the whole frame back.
    // The address in `arg0` is this program's own buffer and the kernel reads
    // it through this program's page tables; nothing is dereferenced here.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") arg1 => _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Where the program actually starts.
#[unsafe(no_mangle)]
extern "C" fn consoled_main() -> ! {
    bhaskix_service_domain::serve::<Console>(
        ENDPOINT,
        Ports {
            put: |character| {
                let _ = call(syscall::INVOKE, CONSOLE, method::PUT, character as u64);
            },
            // RFC 0050 for every program that talks to this service, not just
            // the Linux adapter. One invocation per chunk instead of one per
            // byte, so a kernel line cannot land inside a chunk's bytes.
            put_run: |bytes| {
                let _ = call2(
                    syscall::INVOKE,
                    CONSOLE,
                    method::PUT_RUN,
                    bytes.as_ptr() as u64,
                    bytes.len() as u64,
                );
            },
            read: || {
                let (status, byte) = call(syscall::INVOKE, CONSOLE, method::TAKE, 0);
                // A read that failed is not a byte. Zero is the honest answer:
                // the caller asked what was typed, and nothing was.
                if status == status::OK { byte as u8 } else { 0 }
            },
            try_read: || {
                let (status, byte) = call(syscall::INVOKE, CONSOLE, method::POLL, 0);
                if status == status::OK && byte != method::NOTHING {
                    Some(byte as u8)
                } else {
                    None
                }
            },
            // RFC 0042. The record is kernel memory -- the boot report is
            // written before this program exists -- so reading it is a call
            // out, exactly as putting a character is.
            record_size: || {
                let (status, size) = call(syscall::INVOKE, CONSOLE, method::RECORD_SIZE, 0);
                if status == status::OK {
                    size as usize
                } else {
                    0
                }
            },
            record_at: |offset| {
                let (status, packed) =
                    call(syscall::INVOKE, CONSOLE, method::RECORD, offset as u64);
                if status == status::OK {
                    packed.to_le_bytes()
                } else {
                    [0; 8]
                }
            },
            // RFC 0051. Zero on refusal, like the record above: a shell asking
            // what arrived should be told nothing arrived rather than handed an
            // error it cannot act on, and a console this program cannot read is
            // a fault its own boot would already have reported.
            input_stats: |which| {
                let (status, packed) = call(syscall::INVOKE, CONSOLE, method::INPUT_STATS, which);
                if status == status::OK { packed } else { 0 }
            },
        },
    )
}

// The entry point. `rbp` is zeroed so a walker stops here, and the stack is
// aligned because the ABI promises a callee that it is.
core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call consoled_main
    ud2
"#
);
