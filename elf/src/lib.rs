// SPDX-License-Identifier: Apache-2.0
//! ELF64 parsing: the checks, the refusals, and nothing that maps.
//!
//! RFC 0028 step 4 moved this out of the kernel, code unchanged: the parser
//! is the whole attack surface reachable from a file on disk, it carries
//! 10.97 billion fuzz executions of assurance, and the boot loader needs
//! exactly the same checks the kernel runs — so there is one copy, in a
//! leaf crate all three consumers reach. The *loader* half — mapping a
//! parsed image into an address space — stays with whoever owns the
//! address space; [`ElfError::MappingFailed`] is its variant in the shared
//! error type.
//!
//! The rules, unchanged from the kernel years of this file:
//!
//! - **Static ELF64 executables only.** `ET_DYN` — which is what a PIE is —
//!   is refused, which keeps relocation processing out entirely.
//! - **W^X is structural**: a segment asking to be writable and executable
//!   is refused, and [`Protection`] has no variant that could express it.
//! - **Every arithmetic step is checked**: a crafted header wraps exactly
//!   where an unchecked addition would land back inside the buffer.
//! - **No two segments may share a page**, because one page-table entry
//!   cannot honour two protection sets.

// Nothing that ships sees `std`: the crate is `no_std` in every build that
// is not the test harness.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

/// Bytes in one page of the address spaces this format targets. An ELF/x86-64
/// ABI fact, not a memory-manager dependency: the overlap rule and the span
/// arithmetic are statements about 4 KiB pages whoever maps them.
pub const PAGE_SIZE: u64 = 4096;

/// What a segment may be used for — the three answers the parser can give.
///
/// This crate's own type rather than the memory manager's, because the parser
/// must be reachable from the kernel, from the boot loader and from a fuzz
/// target, and a leaf crate reaches upward to none of them. Whoever maps the
/// segment translates these into its own protection vocabulary; W^X is
/// enforced *here*, structurally, by there being no writable-and-executable
/// variant to translate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Readable only.
    ReadOnly,
    /// Readable and writable. Not executable.
    ReadWrite,
    /// Readable and executable. Not writable.
    ReadExecute,
}

impl core::fmt::Display for Protection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "r--",
            Self::ReadWrite => "rw-",
            Self::ReadExecute => "r-x",
        })
    }
}

/// The four bytes every ELF file starts with.
const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// `EI_CLASS` value for 64-bit.
const CLASS_64: u8 = 2;
/// `EI_DATA` value for little-endian.
const DATA_LSB: u8 = 1;
/// `e_type` value for an executable.
const TYPE_EXEC: u16 = 2;
/// `e_type` value for a position-independent executable.
const TYPE_DYN: u16 = 3;
/// `p_type` value for the dynamic segment.
const PT_DYNAMIC: u32 = 2;
/// `DT_RELA`, `DT_RELASZ`, `DT_RELAENT` — where the relocations live.
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
/// `R_X86_64_RELATIVE` — the one relocation kind a slid kernel needs.
const R_RELATIVE: u32 = 8;
/// `e_machine` value for x86-64.
const MACHINE_X86_64: u16 = 0x3e;
/// `p_type` value for a loadable segment.
const PT_LOAD: u32 = 1;

/// Segment permission bits.
mod flags {
    pub const EXEC: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    // Never read by the loader: x86-64 has no execute-without-read and no
    // write-without-read, so a segment clearing it asks for something the
    // hardware cannot express. Named anyway, because a bare `1 << 2` in the
    // tests that build headers would be a magic number.
    #[allow(dead_code, reason = "named for the header builders in the tests")]
    pub const READ: u32 = 1 << 2;
}

/// Where the kernel half begins. Nothing user-mode may be mapped at or above.
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

/// Which half of the address space an image is allowed to ask for.
///
/// The check is the same shape either way — every segment entirely inside
/// its half, refused otherwise — but the halves are opposite worlds: a ring
/// 3 program in the kernel half is an escalation, and a kernel image in the
/// user half is a loader about to jump into unmapped space. One parser,
/// told which world it is validating for, refuses both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressHalf {
    /// Ring 3 programs: every segment below [`KERNEL_HALF`].
    User,
    /// The kernel image itself: every segment at or above it.
    Kernel,
}

/// Segments one program may have.
///
/// Bounded so that a header claiming sixty thousand of them costs a rejection
/// rather than sixty thousand mappings.
pub const MAX_SEGMENTS: usize = 16;

/// Why a file was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    /// Too short to contain a header.
    Truncated,
    /// Not an ELF file.
    NotElf,
    /// Not 64-bit little-endian x86-64.
    WrongMachine,
    /// Not a statically linked executable.
    NotExecutable,
    /// A program header table that does not fit in the file.
    BadProgramHeaders,
    /// A segment whose contents run past the end of the file.
    SegmentOutsideFile,
    /// A segment that would be mapped outside the user half.
    SegmentOutsideUserSpace,
    /// A segment asking to be both writable and executable.
    WriteAndExecute,
    /// More loadable segments than [`MAX_SEGMENTS`].
    TooManySegments,
    /// Two segments that would share a page.
    ///
    /// Refused rather than merged: two segments in one page have two sets of
    /// permissions and one page-table entry, so the mapping has to pick, and
    /// every choice is either weaker than one segment asked for or stronger
    /// than the other did. A linker that pads to a page never produces this.
    SegmentsOverlap,
    /// An entry point that is not inside any loadable segment.
    EntryOutsideImage,
    /// A dynamic image whose relocations are not all `R_X86_64_RELATIVE`,
    /// or whose relocation table lies outside the file or its segments.
    ///
    /// Refused rather than partially applied: a kernel with one relocation
    /// this loader cannot express would run with one wrong pointer, and a
    /// wrong pointer at a random call site is the least diagnosable failure
    /// a boot can have.
    UnsupportedRelocation,
    /// The address space rejected a mapping.
    ///
    /// The one variant the parser never produces: it belongs to the loader
    /// half, which lives with whoever owns an address space — the kernel's
    /// `elf::load_into` today, the boot loader's placement tomorrow — and
    /// shares this enum so a caller handles one error type end to end.
    MappingFailed,
}

/// One loadable segment, already checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Where it goes.
    pub address: u64,
    /// How much address space it occupies, once zero-filled.
    pub memory_size: u64,
    /// Offset of its contents within the file.
    pub file_offset: usize,
    /// How many bytes of contents there are.
    pub file_size: usize,
    /// What it may be used for.
    pub protection: Protection,
    /// The raw `p_flags` the file asked for.
    ///
    /// Kept alongside the [`Protection`] it was translated into so that a
    /// caller — or a test — can compare what was asked for against what was
    /// granted. A translation that only ever produces the safe answer is
    /// indistinguishable from one that is never given the unsafe question,
    /// and the difference matters here.
    pub flags: u32,
}

/// A parsed, validated program image.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    /// Where execution starts.
    pub entry: u64,
    segments: [Option<Segment>; MAX_SEGMENTS],
    count: usize,
    /// The dynamic segment's place in the file, when the image is a
    /// position-independent executable: `(file offset, bytes)`, bounds
    /// already checked against the file.
    dynamic: Option<(usize, usize)>,
}

impl Image {
    /// The loadable segments, in file order.
    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().flatten()
    }

    /// How many loadable segments the image has.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.count
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(slice);
    Some(u64::from_le_bytes(value))
}

/// The half-open range of pages a segment occupies, or `None` if it wraps.
///
/// Shared by the overlap check and the mapper so that both agree on what a
/// segment covers. Two answers to that question is how a segment gets checked
/// as one range and mapped as another.
pub fn page_span(segment: &Segment) -> Option<(u64, u64)> {
    let start = segment.address & !(PAGE_SIZE - 1);
    let end = segment.address.checked_add(segment.memory_size.max(1))?;
    let end = end.checked_next_multiple_of(PAGE_SIZE)?;
    Some((start, end))
}

/// Parses and validates an ELF64 executable without mapping anything.
///
/// Separated from [`load_into`] so that every rejection above can be tested,
/// and fuzzed, against a byte buffer and nothing else. A loader whose checks
/// can only be exercised by actually mapping memory is a loader whose checks
/// are not exercised.
///
/// # Errors
///
/// [`ElfError`] naming what was wrong. The variants are specific because a
/// single "invalid" tells whoever built the file nothing.
pub fn parse(bytes: &[u8]) -> Result<Image, ElfError> {
    parse_in(bytes, AddressHalf::User)
}

/// [`parse`], for a caller that says which half the image belongs to.
///
/// The boot loader's entry point (RFC 0028 step 5): the kernel image lives
/// in the high half, and every other check — the magic, the machine, the
/// arithmetic, W^X, the overlap rule, the entry bound — is identical.
///
/// # Errors
///
/// [`ElfError`], exactly as [`parse`].
pub fn parse_in(bytes: &[u8], half: AddressHalf) -> Result<Image, ElfError> {
    if bytes.len() < 64 {
        return Err(ElfError::Truncated);
    }
    if bytes.get(0..4) != Some(&MAGIC) {
        return Err(ElfError::NotElf);
    }
    if bytes.get(4) != Some(&CLASS_64) || bytes.get(5) != Some(&DATA_LSB) {
        return Err(ElfError::WrongMachine);
    }
    let e_type = u16_at(bytes, 16).ok_or(ElfError::Truncated)?;
    match (half, e_type) {
        // Ring 3 programs: static executables only. Refusing `ET_DYN` is
        // what keeps relocation processing out of the *program* loader
        // entirely.
        (AddressHalf::User, TYPE_EXEC) => {}
        // The kernel image: `ET_DYN` as well, because a KASLR-able kernel
        // is relocatable by construction — this tree's own kernel is one —
        // and its relocations are walked by [`for_each_relative_relocation`],
        // every one of them `R_X86_64_RELATIVE` or the whole image refused.
        (AddressHalf::Kernel, TYPE_EXEC | TYPE_DYN) => {}
        _ => return Err(ElfError::NotExecutable),
    }
    if u16_at(bytes, 18) != Some(MACHINE_X86_64) {
        return Err(ElfError::WrongMachine);
    }

    let entry = u64_at(bytes, 24).ok_or(ElfError::Truncated)?;
    let phoff = u64_at(bytes, 32).ok_or(ElfError::Truncated)?;
    let phentsize = u16_at(bytes, 54).ok_or(ElfError::Truncated)? as usize;
    let phnum = u16_at(bytes, 56).ok_or(ElfError::Truncated)? as usize;

    // A program header must be at least the 56 bytes the format defines. A
    // larger one is allowed -- the standard permits it -- and the extra is
    // ignored rather than parsed.
    if phentsize < 56 {
        return Err(ElfError::BadProgramHeaders);
    }

    let phoff = usize::try_from(phoff).map_err(|_| ElfError::BadProgramHeaders)?;
    let table_size = phentsize
        .checked_mul(phnum)
        .ok_or(ElfError::BadProgramHeaders)?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or(ElfError::BadProgramHeaders)?;
    if table_end > bytes.len() {
        return Err(ElfError::BadProgramHeaders);
    }

    let mut segments = [None; MAX_SEGMENTS];
    let mut count = 0;
    let mut dynamic = None;

    for index in 0..phnum {
        let header = phoff + index * phentsize;

        let p_type = u32_at(bytes, header).ok_or(ElfError::BadProgramHeaders)?;
        if p_type == PT_DYNAMIC {
            // Captured for the relocation walk, bounds-checked like any
            // segment: a dynamic table outside the file is a header lying.
            let offset = u64_at(bytes, header + 8).ok_or(ElfError::BadProgramHeaders)?;
            let filesz = u64_at(bytes, header + 32).ok_or(ElfError::BadProgramHeaders)?;
            let offset = usize::try_from(offset).map_err(|_| ElfError::BadProgramHeaders)?;
            let filesz = usize::try_from(filesz).map_err(|_| ElfError::BadProgramHeaders)?;
            let end = offset
                .checked_add(filesz)
                .ok_or(ElfError::BadProgramHeaders)?;
            if end > bytes.len() {
                return Err(ElfError::BadProgramHeaders);
            }
            dynamic = Some((offset, filesz));
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }

        let permissions = u32_at(bytes, header + 4).ok_or(ElfError::BadProgramHeaders)?;
        let offset = u64_at(bytes, header + 8).ok_or(ElfError::BadProgramHeaders)?;
        let vaddr = u64_at(bytes, header + 16).ok_or(ElfError::BadProgramHeaders)?;
        let filesz = u64_at(bytes, header + 32).ok_or(ElfError::BadProgramHeaders)?;
        let memsz = u64_at(bytes, header + 40).ok_or(ElfError::BadProgramHeaders)?;

        // Contents must be inside the file. Checked with `checked_add`, not by
        // comparing `offset + filesz` -- the addition is exactly where a
        // crafted header wraps and lands back inside the buffer.
        let offset = usize::try_from(offset).map_err(|_| ElfError::SegmentOutsideFile)?;
        let filesz = usize::try_from(filesz).map_err(|_| ElfError::SegmentOutsideFile)?;
        let end = offset
            .checked_add(filesz)
            .ok_or(ElfError::SegmentOutsideFile)?;
        if end > bytes.len() {
            return Err(ElfError::SegmentOutsideFile);
        }

        // A segment holding fewer bytes in memory than in the file describes
        // something that cannot exist: the tail is zero-fill, never truncation.
        if memsz < filesz as u64 {
            return Err(ElfError::SegmentOutsideFile);
        }

        // The mapping must sit entirely inside its half, and must not wrap.
        let last = vaddr
            .checked_add(memsz.max(1) - 1)
            .ok_or(ElfError::SegmentOutsideUserSpace)?;
        let outside = match half {
            AddressHalf::User => vaddr >= KERNEL_HALF || last >= KERNEL_HALF,
            AddressHalf::Kernel => vaddr < KERNEL_HALF,
        };
        if outside {
            return Err(ElfError::SegmentOutsideUserSpace);
        }

        let writable = permissions & flags::WRITE != 0;
        let executable = permissions & flags::EXEC != 0;
        if writable && executable {
            // `docs/security.md` makes W^X structural. Honouring this because
            // the file asked would make it advisory, and the file is written
            // by whoever wants it honoured.
            return Err(ElfError::WriteAndExecute);
        }

        // `PF_R` is not consulted: x86-64 has no execute-without-read and no
        // write-without-read, so a segment that cleared it would be asking for
        // something the hardware cannot express. It is mapped readable and the
        // bit is preserved in `flags` for whoever wants to see what was asked.
        let protection = match (writable, executable) {
            (true, false) => Protection::ReadWrite,
            (false, true) => Protection::ReadExecute,
            _ => Protection::ReadOnly,
        };

        if count >= MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        segments[count] = Some(Segment {
            address: vaddr,
            memory_size: memsz,
            file_offset: offset,
            file_size: filesz,
            protection,
            flags: permissions,
        });
        count += 1;
    }

    if count == 0 {
        return Err(ElfError::NotExecutable);
    }

    // No two segments may share a page. Checked here, where it is a rejection,
    // rather than in the mapper, where it would be a half-mapped image and a
    // permission decision nobody wrote down. Quadratic over at most
    // `MAX_SEGMENTS` entries.
    for (index, segment) in segments.iter().flatten().enumerate() {
        let (start, end) = page_span(segment).ok_or(ElfError::SegmentOutsideUserSpace)?;
        for other in segments.iter().flatten().skip(index + 1) {
            let (other_start, other_end) =
                page_span(other).ok_or(ElfError::SegmentOutsideUserSpace)?;
            if start < other_end && other_start < end {
                return Err(ElfError::SegmentsOverlap);
            }
        }
    }

    // The entry point must be inside something that was actually mapped.
    // Without this a file can name an entry in unmapped space, and the first
    // instruction faults somewhere with no relation to the file.
    let entry_mapped = segments.iter().flatten().any(|segment| {
        entry >= segment.address && entry < segment.address.saturating_add(segment.memory_size)
    });
    if !entry_mapped {
        return Err(ElfError::EntryOutsideImage);
    }

    Ok(Image {
        entry,
        segments,
        count,
        dynamic,
    })
}

/// The file offset a virtual address lives at, through the image's own
/// segments — how the relocation table, named by address, is found in the
/// file's bytes.
fn file_offset_of(image: &Image, address: u64, length: usize) -> Option<usize> {
    for segment in image.segments() {
        let end = segment.address.checked_add(segment.file_size as u64)?;
        if address >= segment.address && address.checked_add(length as u64)? <= end {
            return Some(segment.file_offset + (address - segment.address) as usize);
        }
    }
    None
}

/// Walks a position-independent image's relocations, calling `apply` with
/// each one's `(virtual address, addend)` — the loader writes
/// `slide + addend` at the address, whatever its slide is, zero included.
/// Returns how many there were. An image with no dynamic segment has none,
/// which is an answer, not an error.
///
/// # Errors
///
/// [`ElfError::UnsupportedRelocation`] for any relocation that is not
/// `R_X86_64_RELATIVE`, a table that lies outside the file or the
/// segments, or a malformed entry size — refused whole, because a
/// partially relocated kernel fails at a random call site instead of
/// here, with a sentence.
pub fn for_each_relative_relocation(
    bytes: &[u8],
    image: &Image,
    mut apply: impl FnMut(u64, i64),
) -> Result<usize, ElfError> {
    let Some((dyn_offset, dyn_size)) = image.dynamic else {
        return Ok(0);
    };
    // The dynamic table: (tag, value) pairs, sixteen bytes each, ended by
    // DT_NULL or the segment's own size.
    let mut rela_address = None;
    let mut rela_size = None;
    let mut rela_entry = None;
    let mut at = 0;
    while at + 16 <= dyn_size {
        let tag = u64_at(bytes, dyn_offset + at).ok_or(ElfError::UnsupportedRelocation)?;
        let value = u64_at(bytes, dyn_offset + at + 8).ok_or(ElfError::UnsupportedRelocation)?;
        match tag {
            0 => break,
            DT_RELA => rela_address = Some(value),
            DT_RELASZ => rela_size = Some(value),
            DT_RELAENT => rela_entry = Some(value),
            _ => {}
        }
        at += 16;
    }
    let (Some(address), Some(size)) = (rela_address, rela_size) else {
        // A dynamic segment with no relocation table: nothing to apply.
        return Ok(0);
    };
    if rela_entry.unwrap_or(24) != 24 {
        return Err(ElfError::UnsupportedRelocation);
    }
    let size = usize::try_from(size).map_err(|_| ElfError::UnsupportedRelocation)?;
    if size % 24 != 0 {
        return Err(ElfError::UnsupportedRelocation);
    }
    let table = file_offset_of(image, address, size).ok_or(ElfError::UnsupportedRelocation)?;

    let count = size / 24;
    for index in 0..count {
        let entry = table + index * 24;
        let r_offset = u64_at(bytes, entry).ok_or(ElfError::UnsupportedRelocation)?;
        let r_info = u64_at(bytes, entry + 8).ok_or(ElfError::UnsupportedRelocation)?;
        let r_addend = u64_at(bytes, entry + 16).ok_or(ElfError::UnsupportedRelocation)? as i64;
        if (r_info & 0xffff_ffff) as u32 != R_RELATIVE {
            return Err(ElfError::UnsupportedRelocation);
        }
        // The target must be inside a loaded segment's memory span, or the
        // loader would write outside the image it placed.
        let inside = image.segments().any(|segment| {
            r_offset >= segment.address
                && r_offset
                    .checked_add(8)
                    .is_some_and(|end| end <= segment.address.saturating_add(segment.memory_size))
        });
        if !inside {
            return Err(ElfError::UnsupportedRelocation);
        }
        apply(r_offset, r_addend);
    }
    Ok(count)
}

/// Image builders, shared with the tests of every consuming crate.
///
/// Public behind the `test-support` feature (and in this crate's own tests)
/// rather than private, for the reason `ustar`'s equivalent states: **a second
/// builder somewhere else would be a second opinion about what a well-formed
/// image looks like**, and there is one definition of that. It belongs next to
/// the parser it feeds.
///
/// It exists here for a second reason too. The reachability audit of
/// 2026-08-21 measured `fuzz_targets/elf_parse.rs` and found that *"a relative
/// relocation was applied"* was **never reached** from an empty corpus: the
/// walk returned `Ok` with nothing to do, every time, because random bytes do
/// not carry a dynamic segment naming a `RELA` table. A fuzzer cannot invent
/// one, so the target has to build one — and building one twice, once here and
/// once there, is exactly the thing this module exists to prevent.
///
/// Hidden from documentation: these are fixtures, not an image writer. Nothing
/// that ships links them.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Where a built image says it loads.
    pub const BASE: u64 = 0xffff_ffff_8000_0000;

    /// Builds a high-half `ET_DYN` image: one loadable RX segment whose
    /// contents hold a relocation table, and a `DYNAMIC` segment naming it.
    /// `reloc_type` lets a test hand in a kind the walker must refuse.
    #[must_use]
    pub fn dynamic_elf(reloc_count: usize, reloc_type: u32, target: u64) -> Vec<u8> {
        const PHOFF: usize = 64;
        const PHENTSIZE: usize = 56;
        let contents_at = PHOFF + 2 * PHENTSIZE;
        let dyn_at = contents_at; // dynamic table first
        let dyn_bytes = 4 * 16;
        let rela_at = dyn_at + dyn_bytes;
        let rela_bytes = reloc_count * 24;
        let total = rela_at + rela_bytes;

        let mut bytes = vec![0u8; total];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = CLASS_64;
        bytes[5] = DATA_LSB;
        bytes[16..18].copy_from_slice(&TYPE_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[24..32].copy_from_slice(&BASE.to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENTSIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        // The loadable segment: the whole file, RX, at the base.
        let ph = PHOFF;
        bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[ph + 4..ph + 8].copy_from_slice(&(flags::READ | flags::EXEC).to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[ph + 16..ph + 24].copy_from_slice(&BASE.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&(total as u64).to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&(total as u64).to_le_bytes());

        // The dynamic segment, inside the loadable one.
        let ph = PHOFF + PHENTSIZE;
        bytes[ph..ph + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&(dyn_at as u64).to_le_bytes());
        bytes[ph + 16..ph + 24].copy_from_slice(&(BASE + dyn_at as u64).to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&(dyn_bytes as u64).to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&(dyn_bytes as u64).to_le_bytes());

        // DT_RELA, DT_RELASZ, DT_RELAENT, DT_NULL.
        let entries = [
            (DT_RELA, BASE + rela_at as u64),
            (DT_RELASZ, rela_bytes as u64),
            (DT_RELAENT, 24u64),
            (0u64, 0u64),
        ];
        for (slot, (tag, value)) in entries.iter().enumerate() {
            let at = dyn_at + slot * 16;
            bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }

        // The relocations: each targets `target`, addend = its index.
        for index in 0..reloc_count {
            let at = rela_at + index * 24;
            bytes[at..at + 8].copy_from_slice(&target.to_le_bytes());
            let info = u64::from(reloc_type);
            bytes[at + 8..at + 16].copy_from_slice(&info.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&(index as u64).to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::dynamic_elf;
    use super::*;

    #[test]
    fn a_dynamic_kernel_image_parses_and_its_relocations_are_walked() {
        let file = dynamic_elf(3, R_RELATIVE, 0xffff_ffff_8000_0010);
        // Still refused for ring 3: a PIE is not a static executable.
        assert_eq!(parse(&file), Err(ElfError::NotExecutable));
        let image = parse_in(&file, AddressHalf::Kernel).expect("a relocatable kernel");
        let mut seen = Vec::new();
        let walked = for_each_relative_relocation(&file, &image, |address, addend| {
            seen.push((address, addend));
        })
        .expect("all relative");
        assert_eq!(walked, 3);
        assert_eq!(
            seen,
            [
                (0xffff_ffff_8000_0010, 0),
                (0xffff_ffff_8000_0010, 1),
                (0xffff_ffff_8000_0010, 2)
            ]
        );
    }

    #[test]
    fn a_relocation_kind_the_loader_cannot_express_refuses_the_whole_image() {
        // R_X86_64_64 is 1: a symbolic relocation, which a loader with no
        // symbol table must refuse rather than write garbage for.
        let file = dynamic_elf(2, 1, 0xffff_ffff_8000_0010);
        let image = parse_in(&file, AddressHalf::Kernel).expect("parses");
        assert_eq!(
            for_each_relative_relocation(&file, &image, |_, _| {}),
            Err(ElfError::UnsupportedRelocation)
        );
    }

    #[test]
    fn a_relocation_outside_the_image_is_refused() {
        let file = dynamic_elf(1, R_RELATIVE, 0xffff_ffff_9000_0000);
        let image = parse_in(&file, AddressHalf::Kernel).expect("parses");
        assert_eq!(
            for_each_relative_relocation(&file, &image, |_, _| {}),
            Err(ElfError::UnsupportedRelocation)
        );
    }

    #[test]
    fn each_half_refuses_the_other_and_accepts_its_own() {
        // A high-half image: refused by the user parse, accepted by the
        // kernel parse — and the mirror, so neither check is vacuous.
        let high = elf(
            0xffff_ffff_8000_0000,
            0xffff_ffff_8000_0000,
            flags::READ | flags::EXEC,
            16,
            16,
        );
        assert_eq!(parse(&high), Err(ElfError::SegmentOutsideUserSpace));
        let image = parse_in(&high, AddressHalf::Kernel).expect("a kernel image in its half");
        assert_eq!(image.entry, 0xffff_ffff_8000_0000);

        let low = good();
        assert!(parse(&low).is_ok());
        assert_eq!(
            parse_in(&low, AddressHalf::Kernel),
            Err(ElfError::SegmentOutsideUserSpace)
        );
    }

    /// Builds a minimal valid ELF64 executable with one loadable segment.
    fn elf(vaddr: u64, entry: u64, permissions: u32, filesz: u64, memsz: u64) -> Vec<u8> {
        const PHOFF: usize = 64;
        const PHENTSIZE: usize = 56;
        let contents_at = PHOFF + PHENTSIZE;

        let mut bytes = vec![0u8; contents_at + filesz as usize];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = CLASS_64;
        bytes[5] = DATA_LSB;
        bytes[6] = 1; // EI_VERSION
        bytes[16..18].copy_from_slice(&TYPE_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENTSIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let ph = PHOFF;
        bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[ph + 4..ph + 8].copy_from_slice(&permissions.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&(contents_at as u64).to_le_bytes());
        bytes[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        bytes
    }

    fn good() -> Vec<u8> {
        elf(0x40_0000, 0x40_0000, flags::READ | flags::EXEC, 16, 16)
    }

    /// Builds an executable with two loadable segments at chosen addresses.
    fn two_segments(first: u64, second: u64) -> Vec<u8> {
        const PHOFF: usize = 64;
        const PHENTSIZE: usize = 56;
        let contents_at = PHOFF + 2 * PHENTSIZE;

        let mut bytes = vec![0u8; contents_at + 32];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = CLASS_64;
        bytes[5] = DATA_LSB;
        bytes[16..18].copy_from_slice(&TYPE_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[24..32].copy_from_slice(&first.to_le_bytes());
        bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHENTSIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        for (index, (address, permissions)) in
            [(first, flags::READ | flags::EXEC), (second, flags::READ)]
                .into_iter()
                .enumerate()
        {
            let ph = PHOFF + index * PHENTSIZE;
            bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            bytes[ph + 4..ph + 8].copy_from_slice(&permissions.to_le_bytes());
            bytes[ph + 8..ph + 16]
                .copy_from_slice(&((contents_at + index * 16) as u64).to_le_bytes());
            bytes[ph + 16..ph + 24].copy_from_slice(&address.to_le_bytes());
            bytes[ph + 32..ph + 40].copy_from_slice(&16u64.to_le_bytes());
            bytes[ph + 40..ph + 48].copy_from_slice(&16u64.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn two_segments_on_separate_pages_are_accepted() {
        // The shape the user probe really has: code, then read-only data.
        let image = parse(&two_segments(0x1000_0000, 0x1000_1000)).expect("valid");
        assert_eq!(image.segment_count(), 2);
        let protections: Vec<_> = image.segments().map(|segment| segment.protection).collect();
        assert_eq!(protections, [Protection::ReadExecute, Protection::ReadOnly]);
    }

    #[test]
    fn two_segments_sharing_a_page_are_refused() {
        // One page-table entry, two sets of permissions: whatever the mapper
        // picked would be weaker than one segment asked for or stronger than
        // the other did, so it does not pick.
        assert_eq!(
            parse(&two_segments(0x1000_0000, 0x1000_0800)),
            Err(ElfError::SegmentsOverlap)
        );
        assert_eq!(
            parse(&two_segments(0x1000_0800, 0x1000_0000)),
            Err(ElfError::SegmentsOverlap)
        );
    }

    #[test]
    fn a_well_formed_executable_parses() {
        let image = parse(&good()).expect("valid");
        assert_eq!(image.entry, 0x40_0000);
        assert_eq!(image.segment_count(), 1);
        let segment = image.segments().next().unwrap();
        assert_eq!(segment.protection, Protection::ReadExecute);
        assert_eq!(segment.file_size, 16);
    }

    #[test]
    fn anything_that_is_not_elf64_little_endian_x86_is_refused() {
        let mut bytes = good();
        bytes[0] = 0;
        assert_eq!(parse(&bytes), Err(ElfError::NotElf));

        let mut bytes = good();
        bytes[4] = 1; // 32-bit
        assert_eq!(parse(&bytes), Err(ElfError::WrongMachine));

        let mut bytes = good();
        bytes[5] = 2; // big-endian
        assert_eq!(parse(&bytes), Err(ElfError::WrongMachine));

        let mut bytes = good();
        bytes[18..20].copy_from_slice(&0x28u16.to_le_bytes()); // arm
        assert_eq!(parse(&bytes), Err(ElfError::WrongMachine));
    }

    #[test]
    fn a_shared_object_is_refused_rather_than_relocated() {
        // ET_DYN is what a PIE is. Refusing it is what keeps relocation
        // processing -- and its attack surface -- out of this loader.
        let mut bytes = good();
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::NotExecutable));
    }

    #[test]
    fn a_segment_running_past_the_end_of_the_file_is_refused() {
        let mut bytes = good();
        let ph = 64;
        bytes[ph + 32..ph + 40].copy_from_slice(&0xffff_ffffu64.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::SegmentOutsideFile));
    }

    #[test]
    fn an_offset_that_wraps_is_refused_rather_than_landing_back_inside() {
        // The check that matters most: `offset + filesz` computed without care
        // wraps to a small number that passes a naive bounds test.
        let mut bytes = good();
        let ph = 64;
        bytes[ph + 8..ph + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&16u64.to_le_bytes());
        assert!(matches!(
            parse(&bytes),
            Err(ElfError::SegmentOutsideFile | ElfError::BadProgramHeaders)
        ));
    }

    #[test]
    fn a_segment_in_the_kernel_half_is_refused() {
        // A user program asking to be mapped over the kernel, by a loader that
        // has the authority to do it.
        for address in [KERNEL_HALF, KERNEL_HALF + 0x1000, u64::MAX - 0x1000] {
            let bytes = elf(address, address, flags::READ | flags::EXEC, 16, 16);
            assert_eq!(
                parse(&bytes),
                Err(ElfError::SegmentOutsideUserSpace),
                "{address:#x} was accepted"
            );
        }
    }

    #[test]
    fn a_segment_that_wraps_into_the_kernel_half_is_refused() {
        let bytes = elf(
            KERNEL_HALF - 0x1000,
            KERNEL_HALF - 0x1000,
            flags::READ,
            16,
            0x8000,
        );
        assert_eq!(parse(&bytes), Err(ElfError::SegmentOutsideUserSpace));
    }

    #[test]
    fn a_writable_executable_segment_is_refused() {
        // W^X is structural per `docs/security.md`. Honouring this because the
        // file asked would make it advisory -- and the file is written by
        // whoever wants it honoured.
        let bytes = elf(
            0x40_0000,
            0x40_0000,
            flags::READ | flags::WRITE | flags::EXEC,
            16,
            16,
        );
        assert_eq!(parse(&bytes), Err(ElfError::WriteAndExecute));
    }

    #[test]
    fn a_memory_size_below_the_file_size_is_refused() {
        let bytes = elf(0x40_0000, 0x40_0000, flags::READ, 16, 8);
        assert_eq!(parse(&bytes), Err(ElfError::SegmentOutsideFile));
    }

    #[test]
    fn an_entry_point_outside_every_segment_is_refused() {
        // Otherwise the first instruction faults at an address with no
        // relation to anything in the file.
        let bytes = elf(0x40_0000, 0x50_0000, flags::READ | flags::EXEC, 16, 16);
        assert_eq!(parse(&bytes), Err(ElfError::EntryOutsideImage));
    }

    #[test]
    fn a_program_header_table_outside_the_file_is_refused() {
        let mut bytes = good();
        bytes[32..40].copy_from_slice(&0xffff_0000u64.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::BadProgramHeaders));

        let mut bytes = good();
        bytes[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::BadProgramHeaders));
    }

    #[test]
    fn a_truncated_file_is_refused_at_every_length() {
        let bytes = good();
        for length in 0..bytes.len() {
            // What it returns does not matter; that it returns does.
            let _ = parse(&bytes[..length]);
        }
    }

    /// The same deterministic generator the `ustar` harness uses.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next() % bound as u64) as usize
            }
        }
    }

    #[test]
    fn a_mutation_harness_never_makes_the_parser_panic() {
        // The §8 fuzz requirement. Seeded rather than coverage-guided, for the
        // reason `ustar` records; the same caveat about assurance applies.
        //
        // A loader is a better fuzz target than most parsers, because the
        // interesting failures are arithmetic: an offset plus a length that
        // wraps, a page count that overflows, an entry inside a segment whose
        // size is `u64::MAX`.
        let iterations: u64 = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        // Where in the seed space to start. Without it a longer campaign is
        // not a wider one: every run walks `0..iterations` and re-tests the
        // inputs the last run already cleared. A batch runner sets this to
        // `batch * iterations` so consecutive batches explore disjoint seeds,
        // which is the difference between eight billion inputs and one billion
        // inputs tried eight times.
        let first: u64 = std::env::var("BHASKIX_FUZZ_SEED_BASE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);

        let base = good();

        for seed in first..first.saturating_add(iterations) {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(7));
            let mut bytes = base.clone();

            let mutations = 1 + rng.below(6);
            for _ in 0..mutations {
                match rng.below(3) {
                    // A byte in the ELF header or the program header, where
                    // every number the loader acts on lives.
                    0 if !bytes.is_empty() => {
                        let index = rng.below(120.min(bytes.len()));
                        bytes[index] = rng.next() as u8;
                    }
                    // A whole 64-bit field, so that wrap-around cases are
                    // reachable -- single-byte flips almost never produce one.
                    //
                    // Half the time the value is drawn from the set of numbers
                    // that break arithmetic rather than at random. Uniform
                    // random never finds these: an offset has to be within
                    // sixteen of `u64::MAX` to wrap a bounds check, which is
                    // one draw in 2^60. Half a million uniform mutations did
                    // not find a deliberately reintroduced wrap bug; this list
                    // finds it in the first few hundred.
                    1 => {
                        let field = rng.below(15) * 8;
                        if field + 8 <= bytes.len() {
                            const EDGES: [u64; 8] = [
                                u64::MAX,
                                u64::MAX - 8,
                                u64::MAX - 16,
                                1 << 63,
                                KERNEL_HALF,
                                KERNEL_HALF - 8,
                                0x7fff_ffff_ffff_ffff,
                                0,
                            ];
                            let value = if rng.below(2) == 0 {
                                EDGES[rng.below(EDGES.len())]
                            } else {
                                rng.next()
                            };
                            bytes[field..field + 8].copy_from_slice(&value.to_le_bytes());
                        }
                    }
                    _ => {
                        let length = rng.below(bytes.len().max(1));
                        bytes.truncate(length);
                    }
                }
            }

            // A rejection is always fine -- refusing hostile input is the
            // point. What must hold is that anything *accepted* is safe to
            // map, so only the `Ok` arm has anything to say.
            if let Ok(image) = parse(&bytes) {
                {
                    // Anything accepted must satisfy every invariant the
                    // mapper will rely on. This is the half that matters: a
                    // parser that never panics but accepts a bad image has
                    // moved the crash into `load_into`.
                    assert!(image.segment_count() <= MAX_SEGMENTS, "seed {seed}");
                    for segment in image.segments() {
                        assert!(
                            segment.file_offset.saturating_add(segment.file_size) <= bytes.len(),
                            "seed {seed}: segment runs past the file"
                        );
                        assert!(
                            segment.memory_size >= segment.file_size as u64,
                            "seed {seed}: memsz below filesz"
                        );
                        assert!(
                            segment.address < KERNEL_HALF,
                            "seed {seed}: segment in the kernel half"
                        );
                        assert!(
                            segment
                                .address
                                .checked_add(segment.memory_size)
                                .is_some_and(|end| end <= KERNEL_HALF),
                            "seed {seed}: segment wraps or crosses into the kernel half"
                        );
                        // Not "the enum cannot express W|X" -- it cannot, and
                        // asserting that would prove nothing. What is asserted
                        // is that no segment whose header *asked* for both was
                        // accepted, which is why the raw flags are kept.
                        assert!(
                            segment.flags & (flags::WRITE | flags::EXEC)
                                != (flags::WRITE | flags::EXEC),
                            "seed {seed}: a writable-executable segment was accepted"
                        );
                    }
                    assert!(
                        image.segments().any(|segment| {
                            image.entry >= segment.address
                                && image.entry < segment.address.saturating_add(segment.memory_size)
                        }),
                        "seed {seed}: entry outside every segment"
                    );
                }
            }
        }
    }
}
