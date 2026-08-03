// SPDX-License-Identifier: Apache-2.0
//! Guarded kernel stacks.
//!
//! Closes a gap open since M2. The kernel has been running on the stack the
//! bootloader provided, which has **no guard page**: the higher-half direct
//! map means the memory below it is mapped and writable, so an overflowing
//! stack silently scribbles over whatever is there — in practice the page
//! tables — until the machine dies in a way no handler can report.
//!
//! A guarded stack puts an unmapped page immediately below it. Overflow then
//! faults on the guard instead of corrupting memory, and because the CPU
//! cannot push a fault frame onto the exhausted stack, that page fault
//! escalates to a double fault — which runs on `IST1` with a known-good stack
//! and reports cleanly (`arch::gdt`).
//!
//! So the two pieces finally meet: M2 built the handler that survives a broken
//! stack, and this is what makes a broken stack detectable rather than silent.
//!
//! # Layout
//!
//! ```text
//!   high   ┌─────────────┐ <- initial RSP
//!          │             │
//!          │    stack    │  STACK_PAGES pages
//!          │             │
//!          ├─────────────┤ <- stack bottom
//!   low    │ guard page  │  unmapped; touching it faults
//!          └─────────────┘
//! ```

use bhaskix_arch::paging::{self, flags};
use bhaskix_mm::{FRAME_SIZE, Zone};

use crate::heap;
use crate::vm::VmError;

/// Base of the kernel stack area.
///
/// From the address-space layout in `docs/architecture.md` §1, which reserves
/// this range for per-CPU areas and kernel stacks. Well clear of the direct
/// map below it and the kernel image above.
const STACK_AREA_BASE: u64 = 0xffff_a000_0000_0000;

/// Pages per kernel stack. 64 KiB.
///
/// Generous for a kernel that does not recurse and forbids large stack
/// allocations, and small enough that the guard page is reached quickly when
/// something does run away.
pub const STACK_PAGES: u64 = 16;

/// A kernel stack with an unmapped guard page below it.
#[derive(Clone, Copy, Debug)]
pub struct GuardedStack {
    /// Address of the guard page. Unmapped.
    pub guard: u64,
    /// Lowest usable stack address.
    pub bottom: u64,
    /// Initial `RSP`: one past the highest usable byte.
    pub top: u64,
}

/// Allocates a guarded stack in the active address space.
///
/// `index` selects a slot in the stack area, so several stacks can coexist —
/// M4 will want one per CPU.
///
/// # Errors
///
/// [`VmError`] if there is no allocator, no memory, or the address is somehow
/// already mapped.
///
/// # Safety
///
/// Must run on the bootstrap CPU while nothing else is modifying page tables.
pub unsafe fn allocate(hhdm_base: u64, index: u64) -> Result<GuardedStack, VmError> {
    // One guard page plus the stack, so consecutive stacks cannot abut: an
    // overflow of one must never land in another.
    let slot = (STACK_PAGES + 1) * FRAME_SIZE;
    let guard = STACK_AREA_BASE + index * slot;
    let bottom = guard + FRAME_SIZE;
    let top = bottom + STACK_PAGES * FRAME_SIZE;

    // SAFETY: the caller guarantees single-CPU init; `active_page_table` is by
    // definition a valid PML4.
    let root = unsafe { paging::active_page_table() };

    // The guard must genuinely be absent. If the bootloader happened to map
    // this range, an "unmapped" guard would silently be a writable page and
    // the whole mechanism would be a no-op that looks like it works.
    // SAFETY: reads page table entries only.
    if unsafe { paging::translate(root, guard, hhdm_base) }.is_some() {
        return Err(VmError::Paging(paging::MapError::AlreadyMapped));
    }

    let result = heap::with(|heap| {
        let pmm = heap.pmm_mut();

        for page in 0..STACK_PAGES {
            let address = bottom + page * FRAME_SIZE;
            let Ok(pfn) = pmm.allocate(0, Zone::Normal) else {
                return Err(VmError::OutOfMemory);
            };
            let physical = u64::from(pfn) * FRAME_SIZE;

            // SAFETY: freshly allocated, so unaliased, and reachable through
            // the direct map. Zeroing on allocation is required by
            // `docs/memory.md` §6.
            unsafe {
                core::ptr::write_bytes((hhdm_base + physical) as *mut u8, 0, FRAME_SIZE as usize);
            }

            // Writable and non-executable: a stack that can be executed from
            // is the classic exploitation primitive, and W^X forbids it
            // (`docs/memory.md` §3).
            let entry = flags::PRESENT | flags::WRITABLE | flags::NO_EXECUTE;

            // SAFETY: single CPU, valid root, page-aligned addresses.
            let mapped = unsafe {
                paging::map_page(root, address, physical, entry, hhdm_base, &mut || {
                    pmm.allocate(0, Zone::Normal)
                        .ok()
                        .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                })
            };
            if let Err(error) = mapped {
                let _ = pmm.free(pfn, 0);
                return Err(VmError::Paging(error));
            }
        }
        Ok(())
    })
    .ok_or(VmError::NoAllocator)?;

    result?;

    Ok(GuardedStack { guard, bottom, top })
}

/// Switches to `stack` and calls `entry(argument)`, which must not return.
///
/// # Why this cannot be written in Rust
///
/// Changing `RSP` invalidates every local in the current frame, so there is no
/// point at which safe Rust code could observe the transition consistently.
/// The switch and the call have to be one uninterrupted sequence.
///
/// # Safety
///
/// The caller must ensure:
/// - `stack` is a 16-byte-aligned address one past the top of a writable,
///   mapped stack of adequate size.
/// - Nothing on the current stack is referenced after this point. Locals of
///   the calling frame become unreachable, and any pointer into them dangles.
/// - `entry` never returns. There is no frame to return into.
pub unsafe fn switch_and_continue(stack: u64, argument: u64, entry: extern "C" fn(u64) -> !) -> ! {
    // SAFETY: `noreturn` is honoured -- `entry` is typed as diverging, and the
    // `ud2` after the call is unreachable insurance rather than a real path.
    //
    // `stack` is page-aligned and therefore 16-aligned, so after `call` pushes
    // its return address the callee sees RSP%16 == 8, which is what the SysV
    // ABI requires at function entry. Getting that wrong produces misaligned
    // SSE accesses deep inside unrelated code.
    unsafe {
        core::arch::asm!(
            "mov rsp, {stack}",
            "call {entry}",
            // Unreachable: `entry` diverges. Present so that a bug there
            // faults immediately rather than executing whatever follows.
            "ud2",
            stack = in(reg) stack,
            entry = in(reg) entry,
            in("rdi") argument,
            options(noreturn),
        );
    }
}

/// Reads the current stack pointer, for reporting.
#[must_use]
pub fn current_stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: reading RSP has no side effects and cannot fault.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}
