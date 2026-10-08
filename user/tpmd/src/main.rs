// SPDX-License-Identifier: Apache-2.0
//! The TPM 2.0 service, in a domain of its own -- RFC 0089 step 5c.
//!
//! # What it holds, and what it cannot reach
//!
//! - **one `Frame`**: the TPM's locality-0 register page, which the kernel
//!   found through the ACPI `TPM2` table and checked is not RAM before granting
//!   it. Read and write, no `GRANT` and no `DERIVE`, so the other localities'
//!   pages are not reachable and the page cannot be handed on;
//! - **one endpoint**, on which it answers [`tpm::PCR_READ`] and nothing else.
//!
//! No memory beyond its own, and no DMA window: a CRB TPM does no DMA.
//!
//! # Why there is so little here
//!
//! As in `bin/ahcid`: `user/*` crates are outside `cargo test --workspace`,
//! so nothing that can be got wrong is written here. The command bytes, the
//! response parser and the order of the CRB conversation are all
//! `bhaskix-tpm`'s, host-tested and fuzzed; what is left is the register
//! access that crate deliberately cannot perform. **And it builds no command
//! but `TPM2_PCR_Read`**, so no request can reach an extend or a clear.
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall, tpm};
use bhaskix_tpm::command::{self, ResponseError, SHA256_DIGEST, TPM_ALG_SHA256};
use bhaskix_tpm::crb::{Crb, CrbError, Registers};

/// Slot: the TPM's locality-0 register page.
const PAGE: u64 = 0;
/// Slot: the endpoint this service answers on.
const ENDPOINT: u64 = 1;
/// Where the page is attached in this program's space.
const PAGE_AT: usize = 0x0000_0000_2000_0000;
/// Bytes in it.
const PAGE_BYTES: usize = 0x1000;
/// Reads a wait may spend before it is an error. A TPM command takes
/// milliseconds; this is far past that and far short of forever.
const POLLS: u32 = 50_000_000;

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as an
    // output because the kernel writes the whole frame back on the way out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Blocks until a request arrives, and returns `(status, method, args)`.
fn receive() -> (u64, u64, [u64; 4]) {
    let status: u64;
    let mut badge = ENDPOINT;
    let mut method_out = 0u64;
    let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the system call convention from RFC 0008. Every argument register
    // is an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") syscall::RECV => status,
            inlateout("rdi") badge,
            inlateout("rsi") method_out,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    let _ = badge;
    (status, method_out, [a0, a1, a2, a3])
}

/// Answers the caller this thread received from: `outcome` in the method
/// word, `words` in the four argument words.
fn reply(outcome: u64, words: [u64; 4]) {
    let _ = call(syscall::REPLY, 0, outcome, words);
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The page, as `bhaskix-tpm` drives it. **The only access this program makes
/// to the device**, and it stays inside the page: an offset the crate would
/// never produce is refused here rather than trusted.
struct Page;

impl Registers for Page {
    fn read(&self, offset: usize) -> u32 {
        if offset + 4 > PAGE_BYTES {
            return 0;
        }
        // SAFETY: the page the kernel attached at `PAGE_AT`, device-mapped,
        // and `offset` is inside it and 4-aligned by every caller.
        unsafe { core::ptr::read_volatile((PAGE_AT + offset) as *const u32) }
    }

    fn write(&mut self, offset: usize, value: u32) {
        if offset + 4 > PAGE_BYTES {
            return;
        }
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile((PAGE_AT + offset) as *mut u32, value) }
    }
}

/// Where a CRB command stopped, as the reply says it.
fn device_code(error: CrbError) -> u64 {
    match error {
        CrbError::LocalityNotGranted => 1,
        CrbError::NeverIdle => 2,
        CrbError::NeverReady => 3,
        CrbError::NeverFinished => 4,
        CrbError::CommandTooLarge => 5,
        CrbError::ResponseSize(_) => 6,
    }
}

/// Why a response was refused, as the reply says it.
fn response_code(error: ResponseError) -> u64 {
    match error {
        ResponseError::Truncated => 1,
        ResponseError::Size(_) => 2,
        ResponseError::Tag(_) => 3,
        ResponseError::Code(_) => 4,
        ResponseError::SelectionMismatch => 5,
        ResponseError::NoDigest => 6,
        ResponseError::DigestSize(_) => 7,
    }
}

/// One PCR read, start to reply.
fn answer(crb: &mut Crb<Page>, pcr: u8) {
    let Some(request) = command::pcr_read_command(TPM_ALG_SHA256, pcr) else {
        return reply(tpm::outcome::BAD_REQUEST, [0; 4]);
    };
    let mut response = [0u8; 256];
    let length = match crb.execute(&request, &mut response) {
        Ok(length) => length,
        Err(error) => return reply(tpm::outcome::DEVICE, [device_code(error), 0, 0, 0]),
    };
    match command::parse_pcr_read_response(&response[..length], TPM_ALG_SHA256, pcr, SHA256_DIGEST)
    {
        Ok(digest) => {
            let mut words = [0u64; 4];
            for (word, bytes) in words.iter_mut().zip(digest.chunks(8)) {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(bytes);
                *word = u64::from_be_bytes(eight);
            }
            reply(tpm::outcome::OK, words);
        }
        Err(ResponseError::Code(code)) => reply(tpm::outcome::TPM, [u64::from(code), 0, 0, 0]),
        Err(error) => reply(tpm::outcome::RESPONSE, [response_code(error), 0, 0, 0]),
    }
}

/// Attaches the page, asks for locality 0, and answers PCR reads for as long
/// as anybody asks.
///
/// The entry convention every program here has -- the TSC rate first, which
/// this program does not need -- and the page's **physical** address second,
/// which the CRB's command and response registers must hold.
#[unsafe(no_mangle)]
extern "C" fn tpmd_main(_hertz: u64, page: u64) -> ! {
    if call(
        syscall::INVOKE,
        PAGE,
        method::ATTACH,
        [PAGE_AT as u64, 1, 0, 0],
    )
    .0 != status::OK
    {
        exit()
    }
    let mut crb = Crb::new(Page, page, POLLS);
    let locality = crb.request_locality();
    loop {
        let (received, asked, args) = receive();
        if received != status::OK {
            exit()
        }
        if asked != tpm::PCR_READ || args[0] >= u64::from(command::PCRS) {
            reply(tpm::outcome::BAD_REQUEST, [0; 4]);
            continue;
        }
        if let Err(error) = locality {
            reply(tpm::outcome::DEVICE, [device_code(error), 0, 0, 0]);
            continue;
        }
        answer(&mut crb, args[0] as u8);
    }
}

/// Stops where the kernel can see it.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: `ud2` raises an invalid-opcode fault, which is the point.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
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
    call tpmd_main
    ud2
"#
);
