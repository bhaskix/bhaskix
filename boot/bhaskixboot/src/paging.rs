// SPDX-License-Identifier: Apache-2.0
//! The page tables the kernel will be entered under — RFC 0028 step 5.
//!
//! Three mappings, built after the exit into a pool allocated before it:
//! the **identity map** (the loader keeps executing at its own addresses
//! until the jump), the **higher-half direct map** at the base the kernel
//! expects — both of physical memory and the framebuffer, and both through
//! the *same* page-directory pages, because they map the same bytes — and
//! the **kernel image**, its segments at their linked high-half addresses,
//! W^X held per segment with 4 KiB precision.
//!
//! Four-level on purpose, exactly as RFC 0025 settled for the kernel: the
//! loader hands over the world the kernel was built for.

use bhaskix_elf::{Image, PAGE_SIZE, Protection, page_span};

/// Where the higher-half direct map begins — the base the kernel expects,
/// stated in `docs/architecture.md` and carried in every handoff.
pub const HHDM_BASE: u64 = 0xffff_8000_0000_0000;

/// Present.
const P: u64 = 1 << 0;
/// Writable.
const W: u64 = 1 << 1;
/// A 2 MiB page, in a directory entry.
const LARGE: u64 = 1 << 7;
/// No-execute. Valid because the kernel enables EFER.NXE before paging is
/// this table's problem — and the loader sets it too before loading CR3.
const NX: u64 = 1 << 63;

/// A bump allocator over the pre-exit table pool: frames the firmware gave
/// as `LoaderData`, handed out one at a time, zeroed, never returned. The
/// pool's size is a stated guess and running out is a printed refusal, not
/// a wrap.
pub struct TablePool {
    base: u64,
    frames: u64,
    used: u64,
}

impl TablePool {
    /// A pool over `frames` frames at physical `base` — identity-mapped by
    /// the firmware's own tables, which is what makes writing them sound
    /// before the switch.
    #[must_use]
    pub const fn new(base: u64, frames: u64) -> Self {
        Self {
            base,
            frames,
            used: 0,
        }
    }

    /// How many frames the tables cost, for the report.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    fn take(&mut self) -> Option<u64> {
        if self.used == self.frames {
            return None;
        }
        let frame = self.base + self.used * PAGE_SIZE;
        self.used += 1;
        for offset in 0..(PAGE_SIZE / 8) {
            // SAFETY: a frame inside the pool the firmware allocated to
            // this loader, identity-mapped, zeroed before any entry is
            // read from it.
            unsafe { core::ptr::write_volatile((frame + offset * 8) as *mut u64, 0) };
        }
        Some(frame)
    }
}

/// Reads one entry of a table frame.
fn entry_of(table: u64, index: u64) -> u64 {
    // SAFETY: `table` is a frame from the pool, identity-mapped; the index
    // is masked to nine bits by every caller.
    unsafe { core::ptr::read_volatile((table + index * 8) as *const u64) }
}

/// Writes one entry of a table frame.
fn set_entry(table: u64, index: u64, value: u64) {
    // SAFETY: as in `entry_of`.
    unsafe { core::ptr::write_volatile((table + index * 8) as *mut u64, value) };
}

/// The child table an entry points at, allocating it if the entry is empty.
fn child(pool: &mut TablePool, table: u64, index: u64) -> Option<u64> {
    let entry = entry_of(table, index);
    if entry & P != 0 {
        return Some(entry & 0x000f_ffff_ffff_f000);
    }
    let frame = pool.take()?;
    set_entry(table, index, frame | P | W);
    Some(frame)
}

/// The four-level indices of a virtual address.
const fn indices(virt: u64) -> (u64, u64, u64, u64) {
    (
        (virt >> 39) & 0x1ff,
        (virt >> 30) & 0x1ff,
        (virt >> 21) & 0x1ff,
        (virt >> 12) & 0x1ff,
    )
}

/// The world the kernel is entered under: the root, and the counters the
/// report prints.
pub struct World {
    /// The PML4's physical address — what CR3 will hold.
    pub root: u64,
}

/// Builds the world: identity and HHDM over `[0, physical_top)` plus the
/// framebuffer span, 2 MiB pages, sharing directories; then the kernel's
/// segments, 4 KiB pages, W^X from the image's own protections, backed by
/// `kernel_phys` where the loader placed them.
///
/// Returns `None` — a printed refusal at the caller — if the pool runs dry.
#[must_use]
pub fn build(
    pool: &mut TablePool,
    physical_top: u64,
    framebuffer: Option<(u64, u64)>,
    image: &Image,
    kernel_phys: u64,
    kernel_virt_base: u64,
) -> Option<World> {
    let root = pool.take()?;

    // The direct maps. One set of directories describes physical memory;
    // the identity view and the HHDM view are two PML4 slots pointing at
    // the same directory pages, because they map the same bytes — the
    // sharing is not an optimisation, it is the statement that they agree.
    let top = physical_top.next_multiple_of(1 << 21);
    map_large_span(pool, root, 0, top)?;
    if let Some((base, size)) = framebuffer {
        let start = base & !((1 << 21) - 1);
        let end = (base + size).next_multiple_of(1 << 21);
        map_large_span(pool, root, start, end)?;
    }

    // The kernel's segments, 4 KiB precision, protections from the image —
    // the same `Protection` the parser refused W+X in, translated here into
    // the architecture's bits: writable adds W, non-executable adds NX.
    for segment in image.segments() {
        let (span_start, span_end) = page_span(segment)?;
        let mut virt = span_start;
        while virt < span_end {
            let phys = kernel_phys + (virt - kernel_virt_base);
            let (l4, l3, l2, l1) = indices(virt);
            let pdpt = child(pool, root, l4)?;
            let pd = child(pool, pdpt, l3)?;
            let pt = child(pool, pd, l2)?;
            let mut entry = phys | P;
            match segment.protection {
                Protection::ReadWrite => entry |= W | NX,
                Protection::ReadOnly => entry |= NX,
                Protection::ReadExecute => {}
            }
            set_entry(pt, l1, entry);
            virt += PAGE_SIZE;
        }
    }

    Some(World { root })
}

/// Maps `[start, end)` as 2 MiB pages at both the identity and HHDM views,
/// through shared directories hung under both PML4 slots.
fn map_large_span(pool: &mut TablePool, root: u64, start: u64, end: u64) -> Option<()> {
    let mut at = start;
    while at < end {
        let (identity_l4, l3, l2, _) = indices(at);
        let (hhdm_l4, hhdm_l3, hhdm_l2, _) = indices(HHDM_BASE + at);
        // The physical span is below the canonical hole, so the identity
        // view's lower indices equal the HHDM view's — asserted, because
        // the sharing below silently depends on it.
        debug_assert!(l3 == hhdm_l3 && l2 == hhdm_l2);

        let pdpt = child(pool, root, identity_l4)?;
        // Hang the same PDPT under the HHDM slot: two names, one map.
        if entry_of(root, hhdm_l4) & P == 0 {
            set_entry(root, hhdm_l4, pdpt | P | W);
        }
        let pd = child(pool, pdpt, l3)?;
        set_entry(pd, l2, at | P | W | LARGE);
        at += 1 << 21;
    }
    Some(())
}
