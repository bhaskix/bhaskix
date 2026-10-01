// SPDX-License-Identifier: Apache-2.0
//! The loader half of ELF: mapping a parsed image into an address space.
//!
//! The parser moved to `bhaskix-elf` (RFC 0028 step 4) — one copy of the
//! fuzz-hardened checks, reachable from the kernel, the boot loader and the
//! fuzz target alike — and is re-exported here so every caller keeps seeing
//! one `elf` surface. What stays is what needs an [`AddressSpace`]: placing
//! segments W^X and reporting an entry point.
//!
//! - **W^X while filling, too.** The contents are written through the
//!   direct map, to the physical frames the mapping just allocated — never
//!   through the mapping itself, so a code page is not writable even for
//!   the instant it is being filled.
//! - **No stack or heap.** The caller maps those; the loader places
//!   segments and reports an entry point.
//! - **Zero-fill is lazy** (RFC 0086 step 5, 2026-10-01). The pages of a
//!   segment past its file's last page hold nothing but zeros, and Linux gives
//!   them a frame only when they are touched. This loader gave every one a
//!   frame at load, which was harmless until the first Go `net/http` server:
//!   go 1.27.1 links `crypto/internal/fips140/drbg.memory`, a 32 MiB `.bss`
//!   buffer it barely touches, and the eager load charged all of it to the
//!   domain before the program ran -- the server's 32 MiB envelope was full at
//!   its sixth call. Those pages are now a lazy region, zeroed when first
//!   faulted as every anonymous page is. Executable segments stay eager.

pub use bhaskix_elf::{ElfError, Image, MAX_SEGMENTS, Segment, page_span, parse};

use bhaskix_boot::VirtAddr;
use bhaskix_elf::PAGE_SIZE;
use bhaskix_mm::{Protection, VirtRange};

use crate::vm::AddressSpace;

/// The parser's protection vocabulary, translated into the memory
/// manager's. Total by construction — the parser has no
/// writable-and-executable answer to translate, which is W^X held
/// structurally across the crate boundary.
const fn protection_of(segment: &Segment) -> Protection {
    match segment.protection {
        bhaskix_elf::Protection::ReadOnly => Protection::ReadOnly,
        bhaskix_elf::Protection::ReadWrite => Protection::ReadWrite,
        bhaskix_elf::Protection::ReadExecute => Protection::ReadExecute,
    }
}

/// Maps a parsed image into `space` and returns its entry point.
///
/// The contents are written through the *direct map*, to the physical frames
/// the mapping just allocated — not through the mapping itself, which for a
/// code segment is not writable. A loader that made the segment writable to
/// fill it would create a window in which user-executable memory was also
/// user-writable, which is the thing W^X exists to prevent.
///
/// # Errors
///
/// [`ElfError::MappingFailed`] if the address space refuses a segment.
pub fn load_into(
    image: &Image,
    bytes: &[u8],
    space: &mut AddressSpace,
    hhdm_base: u64,
) -> Result<u64, ElfError> {
    for segment in image.segments() {
        let (start, end) = page_span(segment).ok_or(ElfError::MappingFailed)?;
        // The pages that carry bytes from the file, eagerly; the rest -- zeros
        // alone -- lazily, unless the segment is executable. See the module
        // note. A segment with no file bytes is lazy from its first page.
        let file_end = (segment.address + segment.file_size as u64)
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(ElfError::MappingFailed)?;
        let eager_end = match segment.protection {
            bhaskix_elf::Protection::ReadExecute => end,
            _ if segment.file_size == 0 => start,
            _ => file_end.clamp(start, end),
        };
        let eager = (eager_end - start) / PAGE_SIZE;
        if eager > 0 {
            let range =
                VirtRange::from_pages(VirtAddr(start), eager).ok_or(ElfError::MappingFailed)?;
            space
                .map_anonymous(range, protection_of(segment))
                .map_err(|_| ElfError::MappingFailed)?;
        }
        if end > eager_end {
            let range = VirtRange::from_pages(VirtAddr(eager_end), (end - eager_end) / PAGE_SIZE)
                .ok_or(ElfError::MappingFailed)?;
            space
                .map_anonymous_lazy(range, protection_of(segment))
                .map_err(|_| ElfError::MappingFailed)?;
        }

        // Copy page by page: the mapping is contiguous in virtual space and
        // need not be in physical, so there is no single destination slice.
        let mut copied = 0usize;
        while copied < segment.file_size {
            let virtual_address = segment.address + copied as u64;
            let page = virtual_address & !(PAGE_SIZE - 1);
            let within = (virtual_address - page) as usize;
            let chunk = (PAGE_SIZE as usize - within).min(segment.file_size - copied);

            let physical = space
                .translate(VirtAddr(page))
                .ok_or(ElfError::MappingFailed)?;
            let source = bytes
                .get(segment.file_offset + copied..segment.file_offset + copied + chunk)
                .ok_or(ElfError::SegmentOutsideFile)?;

            // SAFETY: `physical` names a frame this address space just mapped
            // for this segment, reachable through the direct map, and `chunk`
            // is bounded by the remaining space in that page. The source is a
            // checked sub-slice of the file.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    (hhdm_base + (physical & !(PAGE_SIZE - 1)) + within as u64) as *mut u8,
                    chunk,
                );
            }
            copied += chunk;
        }
    }

    Ok(image.entry)
}

#[cfg(test)]
mod tests {
    // The parser's tests — the header builders, every refusal, and the
    // seeded mutation harness — moved to `bhaskix-elf` with the code they
    // test. `load_into` is exercised where it always really was: by every
    // boot's ring 3 loads, gated in the suite.
}
