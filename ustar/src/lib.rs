// SPDX-License-Identifier: Apache-2.0
//! A `ustar` archive reader, for the initial ramdisk.
//!
//! # Every byte here is hostile
//!
//! The archive comes from a file on the boot medium, which anyone able to
//! write that medium controls. Nothing in it may be trusted: not the sizes,
//! not the offsets, not the name lengths, and above all not the checksum,
//! which an attacker computes as easily as a build system does.
//!
//! So this parser is written to the rule that a malformed archive produces a
//! *shorter* listing and never an out-of-bounds read. Every field is bounded
//! against the slice it came from, arithmetic saturates or is checked, and a
//! header that does not make sense ends the iteration rather than being
//! skipped — because "skip the bad one and continue" is how a parser is
//! walked off the end of a buffer one malformed record at a time.
//!
//! # The fuzz requirement, and how it is met
//!
//! `docs/coding-style.md` §8 requires a fuzz target for anything parsing
//! untrusted input. Two things meet it. A **seeded mutation harness** runs
//! in this crate's tests on stable, in CI, on every build — deterministic
//! seeds, so a failure names its input exactly; `BHASKIX_FUZZ_ITERATIONS`
//! raises the count for a soak. And the **coverage-guided target**
//! `fuzz/fuzz_targets/ustar_parse.rs` runs in campaigns — this paragraph
//! said the harness ran "instead" of a fuzzer until 2026-08-18, stale from
//! the day the target closed that deviation; the harness is the weaker,
//! always-on half and the target is the guided one, and both are true now.
//!
//! # Why `ustar` and not something better
//!
//! It is the smallest format that is (a) standardised, (b) produced by a tool
//! already on every developer's machine, and (c) parseable without allocation.
//! The header is 512 bytes of fixed-offset ASCII, the payload follows it
//! aligned to 512, and that is the whole specification.
//!
//! GNU tar's extensions — long names, sparse files, extended headers — are
//! deliberately *not* implemented. The build passes `--format=ustar` so they
//! never appear, and a kernel that quietly understood a superset would be
//! agreeing to parse whatever a future tool decided to emit.
//!
//! # What this is not
//!
//! - **Not writable.** The initrd is read-only by construction.
//! - **Not a filesystem.** There are no directories to open, no cursor, no
//!   permissions. `docs/roadmap.md` M6 puts a VFS above this; this is the
//!   layer that hands it bytes.
//!
//! # Why this is a crate and not a module
//!
//! RFC 0030 step 1 moved it out of the filesystem service, parser unchanged,
//! for RFC 0028's reason: the package format is this same subset, and a
//! second copy of "what is a well-formed header" in the `pkg` crate would be
//! a second opinion. The service re-exports it, so every existing path
//! still names it.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "test-support"))]
extern crate alloc;

/// Every record is a multiple of this, header and payload alike.
pub const BLOCK: usize = 512;

/// Offsets within the 512-byte header, from the format definition.
mod field {
    pub const NAME: (usize, usize) = (0, 100);
    pub const SIZE: (usize, usize) = (124, 12);
    pub const CHECKSUM: (usize, usize) = (148, 8);
    pub const TYPE: usize = 156;
    pub const MAGIC: (usize, usize) = (257, 6);
    pub const PREFIX: (usize, usize) = (345, 155);
}

/// What a record contains.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    /// An ordinary file.
    File,
    /// A directory. Carries no payload.
    Directory,
    /// Something this reader does not interpret — a link, a device node.
    ///
    /// Listed rather than hidden: a consumer that silently dropped entry
    /// kinds it did not understand would make an archive's contents depend on
    /// which reader looked at it.
    Other,
}

/// One archive member.
#[derive(Clone, Copy)]
pub struct Entry<'a> {
    name: &'a [u8],
    data: &'a [u8],
    kind: EntryKind,
}

impl<'a> Entry<'a> {
    /// The member's path, as stored.
    ///
    /// Returned as bytes, not `str`: a name is arbitrary bytes from a hostile
    /// archive, and pretending it is UTF-8 is a decision for whoever displays
    /// it rather than for the parser.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The member's contents. Empty for anything that is not a file.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// What kind of member this is.
    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Whether the name matches `path`, ignoring a leading `./`.
    ///
    /// `tar -C dir .` stores every member with that prefix, and a lookup that
    /// required callers to know so would leak the archiving command into every
    /// call site.
    #[must_use]
    pub fn is(&self, path: &[u8]) -> bool {
        let name = match self.name {
            [b'.', b'/', rest @ ..] => rest,
            name => name,
        };
        let path = match path {
            [b'/', rest @ ..] => rest,
            path => path,
        };
        name == path
    }
}

/// Reads the members of a `ustar` archive.
pub struct Archive<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Archive<'a> {
    /// Reads `bytes` as an archive.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// The member at `path`, if the archive has one.
    ///
    /// Named `lookup` rather than `find`, and `members` rather than `count`,
    /// because this type is also an `Iterator`. An inherent `find` taking
    /// `&self` alongside `Iterator::find` taking `self` is resolved by rules
    /// most readers do not carry in their heads — and it resolved to the
    /// wrong one, consuming the archive at the first call site that used it.
    #[must_use]
    pub fn lookup(&self, path: &[u8]) -> Option<Entry<'a>> {
        Self::new(self.bytes).find(|entry| entry.is(path))
    }

    /// How many members the archive has.
    #[must_use]
    pub fn members(&self) -> usize {
        Self::new(self.bytes).count()
    }
}

/// Reads a NUL-terminated field, bounded by the field's own width.
fn text(header: &[u8], (start, length): (usize, usize)) -> &[u8] {
    let end = start.saturating_add(length).min(header.len());
    let field = header.get(start..end).unwrap_or(&[]);
    match field.iter().position(|byte| *byte == 0) {
        Some(nul) => &field[..nul],
        None => field,
    }
}

/// Reads an octal field.
///
/// Returns `None` on anything that is not a run of octal digits, rather than
/// stopping at the first bad character. A size field of `12x` must not be read
/// as 10 — silently accepting a prefix is how a length is made to disagree
/// with what produced it.
fn octal(header: &[u8], field: (usize, usize)) -> Option<u64> {
    let digits = text(header, field);
    let digits = match digits.iter().position(|byte| *byte == b' ') {
        Some(space) => &digits[..space],
        None => digits,
    };
    let digits = match digits.iter().position(|byte| *byte != b' ') {
        Some(first) => &digits[first..],
        None => digits,
    };
    if digits.is_empty() {
        return None;
    }

    let mut value: u64 = 0;
    for byte in digits {
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Whether the header's own checksum matches its contents.
///
/// Checked, and it proves nothing about trustworthiness — an attacker
/// computes it as easily as `tar` does. What it catches is a *truncated or
/// misaligned* archive, where continuing would read a payload as a header. It
/// is an integrity check, not a security one, and treating it as the latter is
/// the mistake this comment exists to prevent.
fn checksum_matches(header: &[u8]) -> bool {
    let Some(stored) = octal(header, field::CHECKSUM) else {
        return false;
    };

    let (start, length) = field::CHECKSUM;
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        // The checksum field itself is counted as spaces, by definition.
        let value = if index >= start && index < start + length {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
        sum += value;
    }
    sum == stored
}

impl<'a> Iterator for Archive<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        loop {
            let header = self
                .bytes
                .get(self.offset..self.offset.checked_add(BLOCK)?)?;

            // Two consecutive zero blocks end an archive, but one is enough to
            // stop: there is nothing after it worth reading, and requiring the
            // second means a truncated archive is read one block further than
            // its author wrote.
            if header.iter().all(|byte| *byte == 0) {
                return None;
            }

            if text(header, field::MAGIC) != b"ustar" || !checksum_matches(header) {
                // Not a header. Stopping rather than skipping: a reader that
                // hunts for the next plausible header can be walked through a
                // payload chosen to contain one.
                return None;
            }

            let size = octal(header, field::SIZE)?;
            let size = usize::try_from(size).ok()?;

            let kind = match header.get(field::TYPE) {
                Some(b'0' | b'\0') => EntryKind::File,
                Some(b'5') => EntryKind::Directory,
                Some(_) => EntryKind::Other,
                None => return None,
            };

            let payload = self.offset.checked_add(BLOCK)?;
            let data = if kind == EntryKind::File {
                self.bytes.get(payload..payload.checked_add(size)?)?
            } else {
                &[]
            };

            // Payloads are padded to a block boundary.
            let padded = size.checked_add(BLOCK - 1)? / BLOCK * BLOCK;
            self.offset = payload.checked_add(padded)?;

            // A prefix field extends the name, and is almost always empty. It
            // is read but not joined: joining needs a buffer, and this parser
            // does not allocate. A member with a prefix is therefore reported
            // under its short name, which is wrong in a way that is visible
            // rather than silent.
            let name = text(header, field::NAME);
            if name.is_empty() {
                continue;
            }
            let _prefix = text(header, field::PREFIX);

            return Some(Entry { name, data, kind });
        }
    }
}

/// Archive builders, shared with the tests of every consuming crate.
///
/// Public behind the `test-support` feature (and in this crate's own tests)
/// rather than private, because the VFS's tests need archives to resolve
/// paths against and the `pkg` crate's need packages to verify — and a
/// second builder in either would be a second opinion about what a
/// well-formed `ustar` header looks like. There is one definition of that,
/// and it belongs next to the parser it feeds. Hidden from documentation:
/// it is a test fixture, not an archive writer.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    /// Builds a well-formed header for `name` with `size` bytes of payload.
    pub fn header(name: &[u8], size: usize, kind: u8) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[..name.len()].copy_from_slice(name);
        // Mode, uid, gid: plausible octal so the checksum is realistic.
        block[100..107].copy_from_slice(b"0000644");
        block[108..115].copy_from_slice(b"0000000");
        block[116..123].copy_from_slice(b"0000000");

        let mut octal_size = [b'0'; 12];
        let mut value = size;
        let mut index = 10;
        while value > 0 {
            octal_size[index] = b'0' + (value % 8) as u8;
            value /= 8;
            if index == 0 {
                break;
            }
            index -= 1;
        }
        octal_size[11] = 0;
        block[124..136].copy_from_slice(&octal_size);

        block[156] = kind;
        block[257..262].copy_from_slice(b"ustar");
        block[263..265].copy_from_slice(b"00");

        // The checksum, with its own field read as spaces.
        block[148..156].copy_from_slice(b"        ");
        let sum: u64 = block.iter().map(|b| u64::from(*b)).sum();
        let mut digits = [b'0'; 8];
        let mut value = sum;
        let mut index = 5;
        loop {
            digits[index] = b'0' + (value % 8) as u8;
            value /= 8;
            if index == 0 || value == 0 {
                break;
            }
            index -= 1;
        }
        digits[6] = 0;
        digits[7] = b' ';
        block[148..156].copy_from_slice(&digits);
        block
    }

    pub fn archive(members: &[(&[u8], &[u8])]) -> alloc::vec::Vec<u8> {
        let typed: alloc::vec::Vec<_> = members
            .iter()
            .map(|(name, data)| (*name, *data, b'0'))
            .collect();
        archive_of(&typed)
    }

    /// The same, with an explicit type flag per member — directories included.
    pub fn archive_of(members: &[(&[u8], &[u8], u8)]) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        for (name, data, kind) in members {
            bytes.extend_from_slice(&header(name, data.len(), *kind));
            bytes.extend_from_slice(data);
            let padding = (BLOCK - data.len() % BLOCK) % BLOCK;
            bytes.extend(core::iter::repeat_n(0u8, padding));
        }
        bytes.extend(core::iter::repeat_n(0u8, BLOCK * 2));
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{archive, header};
    use super::*;

    #[test]
    fn a_well_formed_archive_lists_its_members() {
        let bytes = archive(&[
            (b"hello.txt".as_slice(), b"hello".as_slice()),
            (b"motd".as_slice(), b"be excellent".as_slice()),
        ]);
        let names: alloc::vec::Vec<_> = Archive::new(&bytes).map(|e| e.name().to_vec()).collect();
        assert_eq!(names, alloc::vec![b"hello.txt".to_vec(), b"motd".to_vec()]);
    }

    #[test]
    fn a_member_is_found_by_name_with_or_without_a_leading_dot_slash() {
        let bytes = archive(&[(b"./etc/hostname".as_slice(), b"bhaskix\n".as_slice())]);
        let archive = Archive::new(&bytes);
        assert_eq!(
            archive.lookup(b"etc/hostname").map(|e| e.data().to_vec()),
            Some(b"bhaskix\n".to_vec())
        );
        assert_eq!(
            archive.lookup(b"/etc/hostname").map(|e| e.data().to_vec()),
            Some(b"bhaskix\n".to_vec())
        );
        assert!(
            archive.lookup(b"etc/hostnam").is_none(),
            "no prefix matching"
        );
    }

    #[test]
    fn a_size_longer_than_the_archive_ends_the_listing() {
        // The whole class of bug this parser exists to not have: a length
        // field that points past the buffer must bound the read, not the
        // buffer bound the length.
        let mut bytes = archive(&[(b"big".as_slice(), b"x".as_slice())]);
        // Rewrite the size to something enormous.
        bytes[124..136].copy_from_slice(b"77777777777\0");
        assert_eq!(Archive::new(&bytes).members(), 0);
    }

    #[test]
    fn a_truncated_archive_stops_rather_than_reading_past_the_end() {
        let bytes = archive(&[(b"hello.txt".as_slice(), b"hello".as_slice())]);
        for length in 0..bytes.len() {
            // Every prefix must terminate. What it yields does not matter;
            // that it returns at all, without reading out of bounds, does.
            let _ = Archive::new(&bytes[..length]).members();
        }
    }

    #[test]
    fn a_header_without_the_magic_is_not_read() {
        let mut bytes = archive(&[(b"hello.txt".as_slice(), b"hello".as_slice())]);
        bytes[257] = b'x';
        assert_eq!(Archive::new(&bytes).members(), 0);
    }

    #[test]
    fn a_bad_checksum_stops_the_listing() {
        // Not because the checksum proves anything about intent -- it does not
        // -- but because a mismatch means the block is not the header it
        // claims to be, and continuing would read a payload as one.
        let mut bytes = archive(&[(b"hello.txt".as_slice(), b"hello".as_slice())]);
        bytes[148] = b'7';
        assert_eq!(Archive::new(&bytes).members(), 0);
    }

    #[test]
    fn a_non_octal_size_is_refused_rather_than_partly_read() {
        let mut bytes = archive(&[(b"hello.txt".as_slice(), b"hello".as_slice())]);
        bytes[124..136].copy_from_slice(b"12x45678901\0");
        assert_eq!(Archive::new(&bytes).members(), 0);
    }

    #[test]
    fn directories_carry_no_payload() {
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&header(b"etc/", 0, b'5'));
        bytes.extend_from_slice(&header(b"etc/hostname", 8, b'0'));
        bytes.extend_from_slice(b"bhaskix\n");
        bytes.extend(core::iter::repeat_n(0u8, BLOCK - 8));
        bytes.extend(core::iter::repeat_n(0u8, BLOCK * 2));

        let entries: alloc::vec::Vec<_> = Archive::new(&bytes).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind(), EntryKind::Directory);
        assert!(entries[0].data().is_empty());
        assert_eq!(entries[1].kind(), EntryKind::File);
        assert_eq!(entries[1].data(), b"bhaskix\n");
    }

    #[test]
    fn an_empty_archive_has_no_members() {
        assert_eq!(Archive::new(&[]).members(), 0);
        assert_eq!(Archive::new(&[0u8; BLOCK * 2]).members(), 0);
    }

    /// A deterministic 64-bit generator.
    ///
    /// Seeded and reproducible on purpose: a harness that finds a crash the
    /// maintainer cannot reproduce has reported a rumour. The seed is printed
    /// with any failure.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // SplitMix64. Small, well-distributed, and no dependency.
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
        // The §8 fuzz requirement, met by a seeded generator rather than a
        // coverage-guided fuzzer -- see the module header for why, and for
        // what that costs in assurance.
        //
        // The assertion is only that the parser *returns*. A corrupt archive
        // has no correct listing, so there is nothing else to check; what is
        // being tested is that no input reads out of bounds, divides by zero,
        // overflows in debug, or loops for ever.
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        let good = archive(&[
            (b"./".as_slice(), b"".as_slice()),
            (b"./README".as_slice(), b"a readme".as_slice()),
            (b"./etc/hostname".as_slice(), b"bhaskix\n".as_slice()),
        ]);

        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1));
            let mut bytes = good.clone();

            // Between one and eight mutations, so that single-byte flips and
            // coordinated multi-byte corruption both occur.
            let mutations = 1 + rng.below(8);
            for _ in 0..mutations {
                match rng.below(4) {
                    // A byte anywhere.
                    0 => {
                        let index = rng.below(bytes.len());
                        bytes[index] = rng.next() as u8;
                    }
                    // A byte in a header field, where the interesting parsing
                    // lives -- blind mutation would mostly hit payload.
                    1 => {
                        let block = rng.below(bytes.len() / BLOCK) * BLOCK;
                        let index = block + rng.below(BLOCK.min(300));
                        if index < bytes.len() {
                            bytes[index] = rng.next() as u8;
                        }
                    }
                    // Truncation.
                    2 => {
                        let length = rng.below(bytes.len().max(1));
                        bytes.truncate(length);
                    }
                    // Extension with noise.
                    _ => {
                        let extra = rng.below(BLOCK);
                        for _ in 0..extra {
                            bytes.push(rng.next() as u8);
                        }
                    }
                }
                if bytes.is_empty() {
                    break;
                }
            }

            // If this panics, the seed identifies the case exactly.
            let count = Archive::new(&bytes).members();
            assert!(
                count <= bytes.len() / BLOCK + 1,
                "seed {seed}: {count} members from {} bytes",
                bytes.len()
            );

            // The same input again must give the same answer: a parser whose
            // result depends on uninitialised state would show up here.
            assert_eq!(
                Archive::new(&bytes).members(),
                count,
                "seed {seed} not stable"
            );
        }
    }

    #[test]
    fn every_single_byte_corruption_terminates() {
        // A cheap stand-in for the fuzz target, run on every build: flip one
        // byte of a good archive to each of a few values and require the
        // parser to return. Nothing asserts *what* it returns -- a corrupt
        // archive has no correct listing -- only that it does.
        let good = archive(&[
            (b"a".as_slice(), b"one".as_slice()),
            (b"b".as_slice(), b"two".as_slice()),
        ]);
        for index in 0..good.len() {
            for value in [0x00u8, 0x2f, 0x37, 0x80, 0xff] {
                let mut bytes = good.clone();
                bytes[index] = value;
                let _ = Archive::new(&bytes).members();
            }
        }
    }
}
