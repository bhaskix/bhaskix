// SPDX-License-Identifier: Apache-2.0
//! The filesystem service, in a domain of its own.
//!
//! This program contains no filesystem code. Every byte of that is in
//! `bhaskix-service-vfs`, which is the same crate the kernel compiles into
//! itself when `services.toml` says `nucleus` — the same parser, the same
//! sessions, the same answers. What this file supplies is the other half: a
//! **context**, built out of system calls rather than out of the kernel's own
//! functions, and a run loop that is `serve::<Filesystem>` instead of
//! `run::<Filesystem>`.
//!
//! That is the whole of RFC 0013's claim, and the reason this file is short.
//! If placing a service somewhere else needed the service to be rewritten, the
//! trait would be decoration.
//!
//! # What it is given, and how
//!
//! - **An endpoint**, at slot 0 of its CSpace. It answers on that, and hands
//!   it back to the kernel for the bulk path — holding it is what says this
//!   program is the filesystem rather than a program pretending to be.
//! - **The filesystem image**, mapped read-only, its address and length in
//!   `rdi` and `rsi` at entry. A domain cannot go and find its storage: it is
//!   handed exactly what it may read, and it can read nothing else.
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall};
use bhaskix_service_vfs::{Bulk, Filesystem, vfs};

/// The slot the kernel puts this domain's endpoint capability in.
///
/// A constant because a context is made of function pointers, which cannot
/// capture — and a convention the kernel and this program share is the honest
/// shape for it: the alternative is a program that goes looking through its own
/// CSpace for something that looks like an endpoint, which is a program that
/// could be given a different one.
const ENDPOINT: u64 = 0;

/// The most one `fs::READ_INTO` can move in a single reply.
///
/// A page, because the bulk path in this placement copies through a buffer in
/// this program's own memory. It is the size of one **piece**, not of one
/// answer: [`fill`] loops, telling the kernel where each piece goes, so a
/// caller asking for more than this gets more than this.
///
/// That distinction was the bug. This constant used to bound the whole reply,
/// so the answer to "read me four pages" was one page and a claim that the file
/// had ended -- while the nucleus placement, which writes through the direct
/// map, returned all four.
const BULK_BYTES: usize = 4096;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A service that panicked
    // has no correct answer to give, and stopping is visible to the kernel
    // where a wrong answer would not be.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> u64 {
    let status: u64;
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side.
    //
    // Every argument register is declared as an output too, because the kernel
    // writes the whole frame back on the way out. Declaring them as inputs
    // said they survive the call, which is not true and which the compiler is
    // entitled to believe. `rcx` and `r11` are destroyed by the instruction.
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

/// The domain placement of the filesystem's one context operation.
///
/// The nucleus writes through the direct map. This cannot: a domain has no way
/// to reach another domain's pages, and must not have. So it reads the bytes
/// into its own buffer and asks the kernel to place them, naming the memory by
/// the slot **the caller** gave — authority the caller already held, which the
/// kernel re-checks. Which caller is not an argument: the kernel knows which
/// message this program is answering, and this program cannot say otherwise.
fn fill(slot: u64, limit: usize, source: &mut dyn FnMut(&mut [u8]) -> usize) -> Option<usize> {
    let mut buffer = [0u8; BULK_BYTES];
    let mut written = 0usize;

    // **A loop, since 2026-08-11, and it is the whole of this fix.** This
    // function used to copy `limit.min(BULK_BYTES)` once and report that as the
    // answer, so a caller asking for more than one page got one page and was
    // told that was the file. The nucleus placement, which has the object in
    // front of it, spanned every frame and returned all of it.
    //
    // The two placements therefore disagreed about how much `READ_INTO` reads
    // -- by a factor of four for a sixteen-kilobyte object, and unboundedly in
    // general. That is the divergence RFC 0013 exists to prevent, and the note
    // below about the *previous* one is why it stings: the same function had
    // already diverged once, on refusals, and the fix then did not ask what
    // else about it might differ.
    //
    // It was invisible because the bulk self-test used a one-page object, where
    // both placements agree by construction.
    loop {
        let want = (limit - written).min(BULK_BYTES);
        let read = source(&mut buffer[..want]);

        // Issued even when there is nothing to write. The nucleus placement
        // checks the caller's capability *before* it reads anything, so a
        // caller with no right to that memory is refused whether or not the
        // file had bytes left. An earlier version of this function returned
        // early on an empty read and therefore answered "fine, nothing" where
        // the nucleus answered "that is not yours" -- the two placements
        // disagreeing about a refusal, which is exactly the divergence this
        // whole design exists to prevent. Found by the negative half of the
        // bulk test and by nothing else.
        //
        // `written` is the offset: where in the caller's object this piece
        // goes. Without it every piece would land at the start and the last one
        // would be the only one that survived.
        let status = call(
            syscall::INVOKE,
            ENDPOINT,
            method::FILL,
            [slot, buffer.as_ptr() as u64, read as u64, written as u64],
        );
        if status != status::OK {
            // The caller named memory it does not hold, or does not hold
            // writable. Indistinguishable from here, and correctly so: this
            // program is told that the authority was not there, not what the
            // caller's CSpace looks like.
            return None;
        }

        written += read;
        if read < want || written >= limit {
            // The source ran out, or the caller has what it asked for. A short
            // read is the end of the file, which is the same thing `fill_from`
            // concludes from a short source.
            return Some(written);
        }
    }
}

/// Where the program actually starts.
///
/// # Safety
///
/// `image` and `length` must describe a mapping this domain holds read-only
/// for its whole life, which is what the kernel gives it at entry.
#[unsafe(no_mangle)]
extern "C" fn vfsd_main(image: u64, length: u64) -> ! {
    // The image is a promise from the kernel: read-only for the life of this
    // program, and the only memory this domain did not allocate itself.
    //
    // SAFETY: `image` and `length` are the mapping the kernel established
    // before entering ring 3, and it is never unmapped. Nothing else in this
    // program constructs a slice from an address.
    let bytes: &'static [u8] =
        unsafe { core::slice::from_raw_parts(image as *const u8, length as usize) };

    // SAFETY: the slice above outlives every use, and this is the only mount:
    // a second one would replace the root under sessions already resolving
    // paths through the first.
    unsafe { vfs::mount(bytes) };

    bhaskix_service_domain::serve::<Filesystem>(
        ENDPOINT,
        Bulk {
            fill,
            // Counted by the kernel in the nucleus placement, and by nobody
            // here. A domain has no way to add to the kernel's number, and
            // inventing a second one that the boot report cannot see would be
            // worse than the gap: the report says where the count comes from.
            refused: || {},
        },
    )
}

// The entry point. `rdi` and `rsi` are what the kernel put there; the ABI
// hands them to `vfsd_main` untouched. `rbp` is zeroed so a walker stops here,
// and the stack is aligned because the ABI promises a callee that it is.
core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call vfsd_main
    ud2
"#
);
