// SPDX-License-Identifier: Apache-2.0
//! The TPM 2.0 service, in a domain of its own -- RFC 0089 step 5c.
//!
//! # What it holds, and what it cannot reach
//!
//! - **one `Frame`**: the TPM's locality-0 register page, which the kernel
//!   found through the ACPI `TPM2` table and checked is not RAM before granting
//!   it. Read and write, no `GRANT` and no `DERIVE`, so the other localities'
//!   pages are not reachable and the page cannot be handed on;
//! - **one endpoint**, on which it answers [`tpm::PCR_READ`] and
//!   [`tpm::REPLAY`] and nothing else.
//!
//! No memory beyond its own, and no DMA window: a CRB TPM does no DMA. Its
//! own memory includes, since RFC 0089 step 6, a read-only copy of the event
//! log at [`tpm::LOG_AT`], which the kernel put there before it started --
//! public bytes, and no capability.
//!
//! # Why there is so little here
//!
//! As in `bin/ahcid`: `user/*` crates are outside `cargo test --workspace`,
//! so nothing that can be got wrong is written here. The command bytes, the
//! response parser and the order of the CRB conversation are all
//! `bhaskix-tpm`'s, host-tested and fuzzed; what is left is the register
//! access that crate deliberately cannot perform. **And it builds no command
//! but `TPM2_PCR_Read`**, so no request can reach an extend or a clear. The
//! replay is `bhaskix-tcglog`'s, host-tested and fuzzed, folding with
//! `bhaskix-pkg`'s SHA-256, which is held to the published vectors.
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall, tpm};
use bhaskix_pkg::sha256::Sha256;
use bhaskix_tcglog::log::Log;
use bhaskix_tcglog::replay::{self, ReplayError};
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

/// One PCR read: its value, or the outcome and detail a reply would carry.
fn read_pcr(crb: &mut Crb<Page>, pcr: u8) -> Result<[u8; SHA256_DIGEST], (u64, u64)> {
    let request =
        command::pcr_read_command(TPM_ALG_SHA256, pcr).ok_or((tpm::outcome::BAD_REQUEST, 0))?;
    let mut response = [0u8; 256];
    let length = crb
        .execute(&request, &mut response)
        .map_err(|error| (tpm::outcome::DEVICE, device_code(error)))?;
    match command::parse_pcr_read_response(&response[..length], TPM_ALG_SHA256, pcr, SHA256_DIGEST)
    {
        Ok(digest) => {
            let mut value = [0u8; SHA256_DIGEST];
            value.copy_from_slice(digest);
            Ok(value)
        }
        Err(ResponseError::Code(code)) => Err((tpm::outcome::TPM, u64::from(code))),
        Err(error) => Err((tpm::outcome::RESPONSE, response_code(error))),
    }
}

/// One PCR read, start to reply.
fn answer(crb: &mut Crb<Page>, pcr: u8) {
    match read_pcr(crb, pcr) {
        Ok(value) => {
            let mut words = [0u64; 4];
            for (word, bytes) in words.iter_mut().zip(value.chunks(8)) {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(bytes);
                *word = u64::from_be_bytes(eight);
            }
            reply(tpm::outcome::OK, words);
        }
        Err((outcome, detail)) => reply(outcome, [detail, 0, 0, 0]),
    }
}

/// `PCR = SHA-256(PCR ‖ digest)`: what the TPM does on an extend.
fn extend(pcr: &[u8; SHA256_DIGEST], digest: &[u8; SHA256_DIGEST]) -> [u8; SHA256_DIGEST] {
    let mut hash = Sha256::new();
    hash.update(pcr);
    hash.update(digest);
    hash.finish()
}

/// Why a replay did not check, as the reply says it.
fn not_checked(error: ReplayError) -> [u64; 4] {
    use tpm::not_checked;
    match error {
        ReplayError::NoSha256Bank => [not_checked::NO_SHA256, 0, 0, 0],
        ReplayError::Sha256Size(size) => [not_checked::SHA256_SIZE, u64::from(size), 0, 0],
        ReplayError::Pcr(pcr) => [not_checked::PCR, u64::from(pcr), 0, 0],
        ReplayError::LateStart => [not_checked::LATE_START, 0, 0, 0],
        ReplayError::Log(_) => [not_checked::WALK, 0, 0, 0],
    }
}

/// The log replayed and every PCR it touched read from the TPM, start to
/// reply -- RFC 0089 step 6.
fn answer_replay(crb: &mut Crb<Page>, log: &[u8]) {
    if log.is_empty() {
        return reply(
            tpm::outcome::NOT_CHECKED,
            [tpm::not_checked::NO_LOG, 0, 0, 0],
        );
    }
    let Ok(parsed) = Log::parse(log) else {
        return reply(
            tpm::outcome::NOT_CHECKED,
            [tpm::not_checked::HEADER, 0, 0, 0],
        );
    };
    let replayed = match replay::replay(&parsed, extend) {
        Ok(replayed) => replayed,
        Err(error) => return reply(tpm::outcome::NOT_CHECKED, not_checked(error)),
    };
    let mut agreeing = 0u32;
    for (pcr, value) in replayed.pcrs.iter().enumerate() {
        if replayed.touched & (1 << pcr) == 0 {
            continue;
        }
        match read_pcr(crb, pcr as u8) {
            Ok(held) if &held == value => agreeing |= 1 << pcr,
            Ok(_) => {}
            Err((outcome, detail)) => return reply(outcome, [detail, 0, 0, 0]),
        }
    }
    reply(
        tpm::outcome::OK,
        [
            u64::from(replayed.touched),
            u64::from(agreeing),
            u64::from(replayed.extended),
            0,
        ],
    );
}

/// Attaches the page, asks for locality 0, and answers PCR reads and replays
/// for as long as anybody asks.
///
/// Not the entry convention most programs here have, the TSC rate first:
/// this one does not need it, and takes the log's length there instead, which
/// the kernel left at [`tpm::LOG_AT`]. The page's **physical** address is
/// second, which the CRB's command and response registers must hold.
#[unsafe(no_mangle)]
extern "C" fn tpmd_main(log_length: u64, page: u64) -> ! {
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
    let log: &[u8] = if log_length == 0 || log_length > tpm::LOG_MAX {
        &[]
    } else {
        // SAFETY: the kernel mapped `log_length` bytes at `LOG_AT` read-only
        // before this program started, and nothing unmaps them.
        unsafe { core::slice::from_raw_parts(tpm::LOG_AT as *const u8, log_length as usize) }
    };
    let mut crb = Crb::new(Page, page, POLLS);
    let locality = crb.request_locality();
    loop {
        let (received, asked, args) = receive();
        if received != status::OK {
            exit()
        }
        let known =
            (asked == tpm::PCR_READ && args[0] < u64::from(command::PCRS)) || asked == tpm::REPLAY;
        if !known {
            reply(tpm::outcome::BAD_REQUEST, [0; 4]);
            continue;
        }
        if let Err(error) = locality {
            reply(tpm::outcome::DEVICE, [device_code(error), 0, 0, 0]);
            continue;
        }
        if asked == tpm::REPLAY {
            answer_replay(&mut crb, log);
        } else {
            answer(&mut crb, args[0] as u8);
        }
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
