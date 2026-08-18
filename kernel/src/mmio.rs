// SPDX-License-Identifier: Apache-2.0
//! Making a device's registers addressable.
//!
//! A device names its registers by physical address, and the kernel reaches
//! them through the direct map — but the direct map covers what the bootloader
//! decided to map, which is memory. Register windows and firmware tables are
//! not memory, and are routinely absent from it.
//!
//! # Uncached, and that is not a performance decision
//!
//! Device pages are mapped with caching off. A cached mapping of a register
//! window means a write can sit in a cache line and a read can be answered
//! from one — so a register would be programmed into the cache and the device
//! would never see it, which presents as hardware that ignores the driver.
//!
//! # Never unmapped
//!
//! There is no counterpart to [`map`]. A device claimed during boot is claimed
//! for the machine's life, and a driver that could unmap its own registers
//! while an interrupt handler was reading them would be a use-after-free with
//! a page fault at the end of it. When devices become removable, this grows a
//! reference count and a reason to have one.

use bhaskix_arch::paging;
use bhaskix_mm::FRAME_SIZE;

use crate::heap;

/// Maps `length` bytes of device memory at `physical`, and returns where.
///
/// Pages the direct map already covers are left alone: their attributes are
/// whatever the bootloader chose, which for real memory is correct and for a
/// register window the caller has to have arranged some other way. Nothing in
/// the tree hits that case — firmware does not map device windows into the
/// direct map — and if something ever does, it will read stale registers
/// rather than fault, which is worth knowing about in advance.
///
/// Returns `None` if the range wraps, or if a page table could not be built.
#[must_use]
pub fn map(physical: u64, length: u64, hhdm: u64) -> Option<u64> {
    if length == 0 {
        return None;
    }
    let last = physical.checked_add(length - 1)?;
    let first_page = physical & !(FRAME_SIZE - 1);
    let last_page = last & !(FRAME_SIZE - 1);
    let virtual_address = hhdm.checked_add(physical)?;

    let mut page = first_page;
    loop {
        let target = hhdm.checked_add(page)?;
        // Any leaf size counts as present: during early boot the active
        // tables are the bootloader's, whose direct map is 2 MiB pages, and
        // a 4 KiB-only probe would report those bytes absent and then fail
        // remapping what was reachable all along.
        // SAFETY: reading the active page table's entries has no side effects.
        let present =
            unsafe { paging::translate_any(paging::active_page_table(), target, hhdm).is_some() };

        if !present {
            let mapped = heap::with(|heap| {
                let pmm = heap.pmm_mut();
                // SAFETY: bootstrap CPU during boot, mapping a device window
                // the caller found in a firmware table or a config register,
                // into the direct map at its usual address.
                unsafe {
                    paging::map_device_page(target, page, hhdm, &mut || {
                        pmm.allocate(0, bhaskix_mm::Zone::Normal)
                            .ok()
                            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                    })
                }
            });
            match mapped {
                Some(Ok(())) => {}
                _ => return None,
            }
        }

        if page == last_page {
            return Some(virtual_address);
        }
        page = page.checked_add(FRAME_SIZE)?;
    }
}
