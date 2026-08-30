// SPDX-License-Identifier: Apache-2.0
//! The Linux personality, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md): the Linux
//! `x86_64` ABI is a *personality* — a translation layer over the
//! capabilities a domain already holds — and never the native interface.
//! This crate is the half of it that needs no machine: what a process's
//! initial state is, and (as tiers land) what each system call's arguments
//! mean, as pure functions over byte buffers.
//!
//! Nothing here holds authority, allocates, or is `unsafe` — `forbid`, with
//! the budget written as zero. The kernel calls in; a host test checks the
//! bytes. That split is what makes the auxv builder testable at all, and the
//! RFC's testing plan names it as the preferred shape.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

pub mod call;
pub mod event;
pub mod exec;
pub mod file;
pub mod memory;
pub mod pipe;
pub mod poll;
pub mod proc;
pub mod process;
pub mod signal;
pub mod socket;
pub mod stack;
pub mod thread;

/// The layout of the adapter's report page, defined once for both rings.
///
/// # Why this is here and not computed twice
///
/// `bin/linuxd` writes this page and the kernel reads it. Until 2026-08-21 each
/// side worked out the offsets for itself — the adapter as a chain of
/// `const … = PREVIOUS + 24`, the kernel as five separate expressions of the
/// form `(8 * 32 + 1024 + 24 + 24) / 8`. Two independent derivations of one
/// layout, in two rings, with nothing checking that they agreed.
///
/// They did not agree. `FAULT_LOG_OFFSET` was `8 * 32 + 64`, four sixteen-byte
/// entries at 320, and its comment said *"past the trace records and the
/// scratch word"* — which was true when the scratch **was** one word. The
/// scratch later became 1,024 bytes starting at 256, so the fault log came to
/// sit **inside it**, and nothing noticed because the kernel never reads the
/// fault log and this program is single-threaded, so no fault is ever handed
/// over between staging bytes and copying them out. A latent corruption held
/// off by an invariant that was never written down for this purpose.
///
/// So the layout lives here, in the crate both rings already depend on, and the
/// scratch is **last** so that widening it cannot walk into anything.
pub mod report {
    /// Eight `mmap` trace records, thirty-two bytes each.
    pub const TRACES_AT: usize = 0;
    /// Where the fault log begins: four sixteen-byte entries.
    pub const FAULT_LOG_AT: usize = 8 * 32;
    /// The exec record: pid, from, to.
    pub const EXEC_AT: usize = FAULT_LOG_AT + 4 * 16;
    /// The file record: outcome, stage, bytes.
    pub const FILE_AT: usize = EXEC_AT + 24;
    /// The fork record: child pid, bytes copied.
    pub const FORK_AT: usize = FILE_AT + 24;
    /// The wait record: collected, status.
    pub const WAIT_AT: usize = FORK_AT + 16;
    /// The supervised-copy measurement: cold cycles, warm cycles.
    pub const COPY_AT: usize = WAIT_AT + 16;
    /// Giving a lent page back: cold cycles, warm cycles.
    ///
    /// [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
    /// made `dir::RELEASE` do more — a revocation now takes the page out of
    /// the borrower's address space — and shipped without a number for it,
    /// because the boot report priced every other path and not this one. Two
    /// halves for the reason [`COPY_AT`]'s comment gives at length: a single
    /// figure here would be the first execution of the path rather than the
    /// cost of using it.
    pub const LEND_AT: usize = COPY_AT + 16;

    /// Where bulk staging begins.
    ///
    /// Rounded up to 512 from the end of the records, so the boundary is
    /// legible in a hex dump rather than merely correct.
    pub const SCRATCH_AT: usize = 512;

    /// How much of the page bulk staging may use.
    ///
    /// **The rest of it.** 1,024 until 2026-08-21, which made a page-sized
    /// transfer four `COPY_OUT` crossings where `MAX_SUPERVISED_COPY` allows
    /// one — a 4× penalty in a constant, found by the measurement RFC 0036
    /// step 2 took for an unrelated reason. 3,584 makes it two. Reaching one
    /// would need a page of its own, which is an object in the manifest and an
    /// entry in `security.md` §1's T11 list, and is a decision rather than a
    /// constant.
    pub const SCRATCH_BYTES: usize = 4096 - SCRATCH_AT;

    /// The page these offsets are inside.
    pub const PAGE: usize = 4096;

    /// Every record ends before the scratch begins.
    const _: () = assert!(LEND_AT + 16 <= SCRATCH_AT);
    /// And the scratch ends inside the page.
    const _: () = assert!(SCRATCH_AT + SCRATCH_BYTES == PAGE);
    /// The fault log is past the traces, which is what it used to claim and
    /// was not.
    const _: () = assert!(FAULT_LOG_AT >= TRACES_AT + 8 * 32);
}
