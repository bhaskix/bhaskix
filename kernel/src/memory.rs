// SPDX-License-Identifier: Apache-2.0
//! Physical memory bring-up.
//!
//! Carries out the handover described in `docs/memory.md` §1: the bump
//! allocator carves out the frame database, the buddy allocator is built on
//! top of it, and the bump allocator is then retired by marking everything it
//! handed out permanently reserved.
//!
//! This module is where the two allocators meet, and it is the only place the
//! kernel turns a physical address into a `&'static mut` slice — which is why
//! it holds most of the kernel's remaining `unsafe`.

use bhaskix_boot::{Handoff, MemoryKind};
use bhaskix_mm::pmm::{Frame, Pfn, Pmm};
use bhaskix_mm::{BumpAllocator, FRAME_SIZE};

use crate::println;

/// Why physical memory bring-up failed.
#[derive(Clone, Copy, Debug)]
pub enum MemoryError {
    /// The bump allocator could not supply enough frames for the database.
    FrameDatabaseTooLarge {
        /// Bytes the database needed.
        needed: u64,
    },
    /// The memory map described no usable memory at all.
    NoUsableMemory,
}

/// Builds the frame database and the buddy allocator.
///
/// # Errors
///
/// See [`MemoryError`]. Either is fatal — a kernel with no physical allocator
/// cannot proceed — but reporting beats faulting.
///
/// # Safety
///
/// Must be called once, on the bootstrap CPU, before any other CPU exists.
/// `handoff` must still be valid: this reads the memory map, so nothing may
/// have reclaimed the bootloader's memory yet.
pub unsafe fn init(handoff: &Handoff, bump: &mut BumpAllocator) -> Result<Pmm, MemoryError> {
    // Size the database by the highest *usable* address rather than the
    // highest address in the map. Reserved regions above the last stick of RAM
    // -- memory-mapped devices, typically -- would otherwise inflate the
    // database by gigabytes to describe frames that can never be allocated.
    let highest_usable = handoff
        .memory_map
        .iter()
        .filter(|region| {
            matches!(
                region.kind,
                MemoryKind::Usable | MemoryKind::BootloaderReclaimable
            )
        })
        .map(|region| region.end().as_u64())
        .max()
        .ok_or(MemoryError::NoUsableMemory)?;

    let frame_count = (highest_usable / FRAME_SIZE) as usize;
    let database_bytes = (frame_count * size_of::<Frame>()) as u64;
    let database_frames = database_bytes.div_ceil(FRAME_SIZE);

    // The database must be one unbroken array, so it is allocated as a single
    // contiguous run. On a PC the first usable region is a ~300 KiB fragment
    // below the legacy hole, far too small -- so this deliberately skips to a
    // region that can hold the whole thing.
    let first = bump.allocate_contiguous(database_frames).map_err(|_| {
        MemoryError::FrameDatabaseTooLarge {
            needed: database_bytes,
        }
    })?;
    let database = first.to_hhdm(handoff.hhdm_base).as_u64() as *mut Frame;

    // SAFETY: `database` addresses `database_frames` consecutive frames just
    // obtained from the bump allocator, reachable through the direct map, and
    // large enough for `frame_count` entries. Nothing else holds a reference:
    // the bump allocator never returns the same frame twice and has no free.
    // `Pmm::new` initialises every entry before any is read.
    let frames: &'static mut [Frame] =
        unsafe { core::slice::from_raw_parts_mut(database, frame_count) };

    let mut pmm = Pmm::new(frames);

    // Hand each usable region to the buddy allocator, minus whatever the bump
    // allocator already consumed.
    //
    // The subtraction has to happen *here*, before the frames reach a free
    // list. Adding everything and then marking the used parts reserved leaves
    // frames that are simultaneously on a free list and reserved, which is
    // exactly the inconsistency `Pmm::check_invariants` rejects -- and which
    // would otherwise hand live memory back out.
    //
    // Bootloader-reclaimable memory is not added at all: the handoff still
    // lives in it (`docs/memory.md` §1).
    let consumed = bump.consumed_ranges();

    for region in handoff.memory_map {
        if region.kind != MemoryKind::Usable {
            continue;
        }
        add_region_excluding(
            &mut pmm,
            region.base.as_u64(),
            region.end().as_u64(),
            consumed,
        );
    }

    Ok(pmm)
}

/// Adds `[start, end)` to the allocator, skipping any part covered by
/// `consumed`.
///
/// `consumed` is sorted ascending and non-overlapping, so this is a single
/// forward walk. Frame-aligned inward at both ends: a partial frame at either
/// edge is not usable memory.
fn add_region_excluding(pmm: &mut Pmm, start: u64, end: u64, consumed: &[(u64, u64)]) {
    let mut cursor = start;

    for &(used_start, used_end) in consumed {
        if used_end <= cursor || used_start >= end {
            continue; // No overlap with what is left of this region.
        }
        if used_start > cursor {
            add_frames(pmm, cursor, used_start.min(end));
        }
        cursor = cursor.max(used_end);
        if cursor >= end {
            return;
        }
    }

    if cursor < end {
        add_frames(pmm, cursor, end);
    }
}

/// Adds the whole frames within `[start, end)`.
fn add_frames(pmm: &mut Pmm, start: u64, end: u64) {
    let first = start.div_ceil(FRAME_SIZE) as Pfn;
    let last = (end / FRAME_SIZE) as Pfn;
    if first < last {
        pmm.add_free_range(first, last);
    }
}

/// Prints what the physical allocator ended up managing.
pub fn report(pmm: &Pmm) {
    let mib = |frames: u64| frames * FRAME_SIZE / (1024 * 1024);
    println!(
        "    frame database {} entries ({} KiB)",
        pmm.total_frames(),
        pmm.total_frames() * size_of::<Frame>() as u64 / 1024
    );
    println!(
        "    buddy pmm      {} MiB free of {} MiB managed",
        mib(pmm.free_frames()),
        mib(pmm.managed_frames())
    );
}

/// Exercises the allocator and asserts nothing leaks.
///
/// This is the frame-leak gate from `docs/memory.md` §7, in the form it can
/// take before there are address spaces to create and destroy. It runs on
/// every boot rather than only under test, because it costs microseconds and
/// because a physical allocator that leaks is the single most expensive bug
/// to find later — it surfaces as unrelated exhaustion, arbitrarily far from
/// the cause.
///
/// Returns whether the allocator came back to exactly its starting state.
pub fn self_test(pmm: &mut Pmm) -> bool {
    use bhaskix_mm::Zone;

    let baseline = pmm.free_frames();
    let mut allocated = [(0u32, 0usize); 64];
    let mut live = 0;

    // A mix of orders, so splitting and coalescing both get exercised rather
    // than a single free list being pushed and popped.
    for index in 0..allocated.len() {
        let order = index % 5;
        match pmm.allocate(order, Zone::Normal) {
            Ok(pfn) => {
                allocated[live] = (pfn, order);
                live += 1;
            }
            Err(_) => break,
        }
    }

    // Free in reverse, which forces coalescing to walk back up the orders.
    for &(pfn, order) in allocated[..live].iter().rev() {
        if pmm.free(pfn, order).is_err() {
            return false;
        }
    }

    let recovered = pmm.free_frames() == baseline;
    let consistent = pmm.check_invariants().is_ok();

    if !recovered {
        println!(
            "    LEAK: {} frames free before, {} after",
            baseline,
            pmm.free_frames()
        );
    }
    if let Err(problem) = pmm.check_invariants() {
        println!("    INVARIANT VIOLATED: {problem}");
    }

    recovered && consistent
}

/// Exercises the kernel heap through the `alloc` types themselves.
///
/// Testing the slab allocator directly is what the host unit tests do. This
/// checks the layer above it — that `#[global_allocator]` is actually wired
/// up, that `Box` and `Vec` reach it, and that the memory they hand back is
/// real and writable on this machine. A slab allocator that passes its own
/// tests but is not connected to `alloc` would look identical from below.
pub fn heap_self_test() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    let before = crate::heap::free_frames();

    // A boxed value, read back to prove the memory is genuinely writable.
    let boxed = Box::new(0xB4A5_C123_u64);
    let boxed_ok = *boxed == 0xB4A5_C123_u64;
    drop(boxed);

    // A vector that grows across several size classes, forcing reallocation
    // and therefore both the allocate and free paths.
    let mut values: Vec<u64> = Vec::new();
    for index in 0..512u64 {
        values.push(index * index);
    }
    let vector_ok = values.len() == 512
        && values[0] == 0
        && values[511] == 511 * 511
        && values
            .iter()
            .enumerate()
            .all(|(i, v)| *v == (i as u64) * (i as u64));
    drop(values);

    let after = crate::heap::free_frames();

    if boxed_ok && vector_ok && before == after {
        println!("    heap           alloc works, no frames leaked");
    } else {
        println!(
            "    heap           FAILED (box {boxed_ok}, vec {vector_ok}, frames {before} -> {after})"
        );
    }
}
