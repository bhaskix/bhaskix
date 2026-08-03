// SPDX-License-Identifier: Apache-2.0
//! Copying to and from user memory.
//!
//! The only sanctioned way kernel code touches a user address
//! (`docs/memory.md` §3). Everything else treats a fault at a kernel-mode
//! instruction as a bug and panics, which is correct — except here, where a
//! bad pointer is *expected input* rather than a defect.
//!
//! # The exception table
//!
//! Each copy routine's faulting instruction registers an entry mapping its own
//! address to a recovery address. When a page fault happens in kernel mode,
//! the handler looks the faulting `RIP` up in that table: if it is there, the
//! fault is not a bug, and execution resumes at the recovery path with an
//! error return. If it is not, the fault is a genuine kernel bug and gets
//! reported as one.
//!
//! This is what makes a hostile user pointer produce an error code instead of
//! taking the machine down — and it is why the table has to be exact. An entry
//! that is missing turns a routine failure into a panic; an entry that is
//! wrong swallows a real bug.
//!
//! # SMAP
//!
//! With SMAP enabled the CPU faults on *any* kernel access to a user page,
//! which is the point: it means an accidental dereference of a user pointer
//! cannot silently work. These routines bracket their accesses with `stac` and
//! `clac` to lift that protection for exactly the instructions that need it.
//!
//! The bracketing is inside the assembly rather than around the call, so the
//! window in which user memory is accessible is a handful of instructions
//! wide and cannot be left open by an early return.

use core::sync::atomic::{AtomicBool, Ordering};

/// One exception-table entry: a faulting address and where to resume.
#[repr(C)]
#[derive(Clone, Copy)]
struct Fixup {
    /// Address of an instruction that may fault.
    fault: u64,
    /// Address to resume at when it does.
    recovery: u64,
}

unsafe extern "C" {
    /// First entry of the exception table, from the link script.
    static __exception_table_start: Fixup;
    /// One past the last entry.
    static __exception_table_end: Fixup;
}

/// Whether SMAP is active, so the copy routines know to toggle `AC`.
///
/// Executing `stac` on a CPU without SMAP raises `#UD`, so this cannot simply
/// be assumed.
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Records that SMAP has been turned on.
pub fn set_smap_enabled(enabled: bool) {
    SMAP_ENABLED.store(enabled, Ordering::Release);
}

/// Whether SMAP is active.
#[must_use]
pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::Acquire)
}

/// Looks `rip` up in the exception table.
///
/// Returns the address to resume at, or `None` if the faulting instruction is
/// not one that is allowed to fault — in which case the caller must treat the
/// fault as the bug it is.
#[must_use]
pub fn fixup_for(rip: u64) -> Option<u64> {
    // SAFETY: both symbols are defined by the link script and bracket a run of
    // `Fixup` records emitted by the assembly below. The subtraction is over
    // pointers into the same object, and the slice covers exactly the entries
    // between them.
    let table = unsafe {
        let start = &raw const __exception_table_start;
        let end = &raw const __exception_table_end;
        let count = end.offset_from(start).max(0) as usize;
        core::slice::from_raw_parts(start, count)
    };

    table
        .iter()
        .find(|entry| entry.fault == rip)
        .map(|entry| entry.recovery)
}

/// Number of entries in the exception table, for reporting.
#[must_use]
pub fn fixup_count() -> usize {
    // SAFETY: as `fixup_for`.
    unsafe {
        let start = &raw const __exception_table_start;
        let end = &raw const __exception_table_end;
        end.offset_from(start).max(0) as usize
    }
}

/// Why a copy failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAccessError {
    /// The user pointer was not accessible. The kernel equivalent of `EFAULT`.
    Fault,
    /// The address is not in the user half of the address space.
    NotUserAddress,
}

/// First address of the kernel half. Anything at or above is not user memory.
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

/// Whether `[address, address + len)` lies wholly in the user half.
///
/// Checked before the copy rather than relying on the fault to catch it. A
/// user pointer aimed at kernel memory would otherwise *succeed*, which is the
/// confused-deputy bug this check exists to prevent — the fault handler cannot
/// tell the difference between a kernel address the caller meant and one an
/// attacker supplied.
#[must_use]
pub fn is_user_range(address: u64, len: usize) -> bool {
    match address.checked_add(len as u64) {
        Some(end) => address < KERNEL_HALF && end <= KERNEL_HALF,
        None => false,
    }
}

unsafe extern "C" {
    /// Copies `len` bytes, returning 0 on success and 1 on fault.
    fn bhaskix_copy_user(destination: *mut u8, source: *const u8, len: usize, smap: u64) -> u64;
}

/// Copies `len` bytes from a user pointer into a kernel buffer.
///
/// # Errors
///
/// [`UserAccessError::NotUserAddress`] if `source` is not wholly in the user
/// half, or [`UserAccessError::Fault`] if it is not mapped.
///
/// # Safety
///
/// `destination` must be valid for `len` bytes of kernel memory. `source` is
/// *not* trusted and needs no guarantees — that is the entire point.
pub unsafe fn copy_from_user(
    destination: *mut u8,
    source: u64,
    len: usize,
) -> Result<(), UserAccessError> {
    if !is_user_range(source, len) {
        return Err(UserAccessError::NotUserAddress);
    }
    // SAFETY: the caller guarantees `destination`. `source` may fault, which is
    // exactly what the exception table handles.
    let faulted = unsafe {
        bhaskix_copy_user(
            destination,
            source as *const u8,
            len,
            u64::from(smap_enabled()),
        )
    };
    if faulted == 0 {
        Ok(())
    } else {
        Err(UserAccessError::Fault)
    }
}

/// Copies `len` bytes from a kernel buffer to a user pointer.
///
/// # Errors
///
/// As [`copy_from_user`].
///
/// # Safety
///
/// `source` must be valid for `len` bytes of kernel memory.
pub unsafe fn copy_to_user(
    destination: u64,
    source: *const u8,
    len: usize,
) -> Result<(), UserAccessError> {
    if !is_user_range(destination, len) {
        return Err(UserAccessError::NotUserAddress);
    }
    // SAFETY: the caller guarantees `source`; `destination` may fault.
    let faulted = unsafe {
        bhaskix_copy_user(
            destination as *mut u8,
            source,
            len,
            u64::from(smap_enabled()),
        )
    };
    if faulted == 0 {
        Ok(())
    } else {
        Err(UserAccessError::Fault)
    }
}

// The copy itself, and the exception-table entry that makes it recoverable.
//
// Written in assembly because the relationship between the faulting
// instruction and its recovery address has to be exact, and no Rust construct
// expresses "if *this* instruction faults, resume *there*".
//
// `rep movsb` is a single instruction covering the whole copy, so one table
// entry suffices however long the copy is. On a fault, RIP points at the
// `rep movsb` itself, which is the address recorded.
core::arch::global_asm!(
    r#"
.section .text
.globl bhaskix_copy_user
.align 16
bhaskix_copy_user:
    // rdi = destination, rsi = source, rdx = length, rcx = smap flag
    mov r8, rcx              // keep the SMAP flag; rcx is the count register
    mov rcx, rdx
    test r8, r8
    jz 2f
    stac                     // permit user access for the copy only
2:
    // The one instruction allowed to fault. Its address is what the exception
    // table records.
3:
    rep movsb
4:
    test r8, r8
    jz 5f
    clac
5:
    xor eax, eax             // success
    ret

    // Recovery. Reached only by the fault handler rewriting RIP.
6:
    test r8, r8
    jz 7f
    clac                     // the window must close on the failure path too
7:
    mov eax, 1               // fault
    ret

.section .exception_table, "a"
.align 8
    .quad 3b                 // faulting instruction
    .quad 6b                 // where to resume
.previous
"#
);
