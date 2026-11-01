// SPDX-License-Identifier: Apache-2.0
//! The slot disk, as arithmetic -- RFC 0100 step 1.
//!
//! A slot disk is a GPT disk with three partitions Bhaskix names by type:
//! a **record** -- one block saying which slot is active and which, if any, is
//! on trial -- and **slots A and B**, each holding a complete boot set (the
//! kernel, the initrd, `boot.conf` and `boot.sig`) behind a one-block header.
//! The native loader reads it through the firmware's Block I/O protocol and
//! decides with this crate; the build tool writes it; a host test drives both.
//!
//! Every structure here is parsed from bytes the loader did not write and
//! cannot trust -- the disk is a device anyone with the machine can rewrite --
//! so every parser is total, every length is bounded before it is used, and
//! every refusal names what failed.
//!
//! **What this does not decide**: whether a set is genuine. That is
//! `boot.sig`'s, checked by `bhaskix-bootsig` after the set is read, exactly as
//! for a set on the ESP. A slot whose set does not verify is refused, and the
//! loader falls back to the other.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// A GUID as it lies on the disk: the first three fields little-endian, as
/// UEFI stores them. Kept as bytes, so a comparison is a comparison of what
/// was read.
pub type Guid = [u8; 16];

/// The record partition's type, `969cace0-879f-45d7-8393-08b4ce7cbf36`.
pub const RECORD_TYPE: Guid = [
    0xe0, 0xac, 0x9c, 0x96, 0x9f, 0x87, 0xd7, 0x45, 0x83, 0x93, 0x08, 0xb4, 0xce, 0x7c, 0xbf, 0x36,
];
/// Slot A's type, `ce2f6916-f0fe-4dc5-9683-ce839d800a72`.
pub const SLOT_A_TYPE: Guid = [
    0x16, 0x69, 0x2f, 0xce, 0xfe, 0xf0, 0xc5, 0x4d, 0x96, 0x83, 0xce, 0x83, 0x9d, 0x80, 0x0a, 0x72,
];
/// Slot B's type, `669e6491-b824-4983-af23-a7c5d7f69482`.
pub const SLOT_B_TYPE: Guid = [
    0x91, 0x64, 0x9e, 0x66, 0x24, 0xb8, 0x83, 0x49, 0xaf, 0x23, 0xa7, 0xc5, 0xd7, 0xf6, 0x94, 0x82,
];

/// The only block size this reads. Every disk this project boots reports 512,
/// and a slot disk is written by this project's tool; a disk of another size
/// is refused rather than half-supported.
pub const BLOCK: usize = 512;

/// The CRC-32 GPT uses: the reflected IEEE polynomial, initial and final
/// value all ones -- what zlib's `crc32` computes, which the build tool uses,
/// and which the firmware's own partition driver checks independently.
#[must_use]
pub const fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    let mut at = 0;
    while at < bytes.len() {
        crc ^= bytes[at] as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            bit += 1;
        }
        at += 1;
    }
    !crc
}

fn word32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn word64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// Why a slot disk, or a part of one, was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A buffer shorter than the structure it should hold.
    Short,
    /// The GPT header's signature is not `EFI PART`.
    NotGpt,
    /// The GPT header's size, entry size or entry count is out of bounds.
    Shape,
    /// The GPT header's CRC does not match.
    HeaderCrc,
    /// The partition entry array's CRC does not match.
    EntriesCrc,
    /// A partition this disk must have is not there, or is there twice.
    Missing,
    /// A partition lies outside the usable range, or ends before it starts.
    Range,
    /// The record's magic or CRC is wrong.
    Record,
    /// A slot's header is not a boot set's header.
    SetHeader,
}

/// The GPT header's fields this reads (UEFI 2.10 §5.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The first usable block.
    pub first_usable: u64,
    /// The last usable block.
    pub last_usable: u64,
    /// The block the entry array starts at.
    pub entries_at: u64,
    /// How many entries.
    pub entries: u32,
    /// Bytes per entry.
    pub entry_size: u32,
    entries_crc: u32,
}

/// Most entries this reads. 128 is what every partitioning tool writes, and
/// a header claiming more would have this read megabytes before it could
/// refuse them.
pub const MAX_ENTRIES: u32 = 128;

impl Header {
    /// Parses the GPT header in `block`, which must be LBA 1.
    ///
    /// # Errors
    ///
    /// Which check failed.
    pub fn parse(block: &[u8]) -> Result<Self, Refusal> {
        if block.len() < BLOCK {
            return Err(Refusal::Short);
        }
        if &block[0..8] != b"EFI PART" {
            return Err(Refusal::NotGpt);
        }
        let size = word32(block, 12) as usize;
        if !(92..=BLOCK).contains(&size) {
            return Err(Refusal::Shape);
        }
        let mut copy = [0u8; BLOCK];
        copy[..size].copy_from_slice(&block[..size]);
        copy[16..20].fill(0);
        if crc32(&copy[..size]) != word32(block, 16) {
            return Err(Refusal::HeaderCrc);
        }
        let header = Self {
            first_usable: word64(block, 40),
            last_usable: word64(block, 48),
            entries_at: word64(block, 72),
            entries: word32(block, 80),
            entry_size: word32(block, 84),
            entries_crc: word32(block, 88),
        };
        if word64(block, 24) != 1
            || header.entries == 0
            || header.entries > MAX_ENTRIES
            || header.entry_size < 128
            || header.entry_size > 512
            || !header.entry_size.is_multiple_of(8)
            || header.first_usable > header.last_usable
        {
            return Err(Refusal::Shape);
        }
        Ok(header)
    }

    /// Bytes the entry array spans, which the caller reads from
    /// [`Header::entries_at`]. Bounded by [`MAX_ENTRIES`] and the entry size.
    #[must_use]
    pub const fn entries_bytes(&self) -> usize {
        self.entries as usize * self.entry_size as usize
    }

    /// Blocks the entry array spans, rounded up.
    #[must_use]
    pub const fn entries_blocks(&self) -> u64 {
        self.entries_bytes().div_ceil(BLOCK) as u64
    }
}

/// A partition: its first and last block, inclusive, as GPT states them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    /// The first block.
    pub first: u64,
    /// The last block, inclusive.
    pub last: u64,
}

impl Partition {
    /// How many bytes it holds.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        (self.last - self.first + 1) * BLOCK as u64
    }
}

/// A slot disk's three partitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The record's partition; its first block is the record.
    pub record: Partition,
    /// Slot A's partition.
    pub a: Partition,
    /// Slot B's partition.
    pub b: Partition,
}

impl Layout {
    /// Finds the three partitions in `entries`, the bytes `header` names.
    ///
    /// # Errors
    ///
    /// [`Refusal::EntriesCrc`] for a damaged array, [`Refusal::Missing`] if
    /// any of the three is absent or present twice, [`Refusal::Range`] for one
    /// outside the usable blocks.
    pub fn find(header: &Header, entries: &[u8]) -> Result<Self, Refusal> {
        let bytes = header.entries_bytes();
        if entries.len() < bytes {
            return Err(Refusal::Short);
        }
        if crc32(&entries[..bytes]) != header.entries_crc {
            return Err(Refusal::EntriesCrc);
        }
        let mut found: [Option<Partition>; 3] = [None; 3];
        for entry in entries[..bytes].chunks(header.entry_size as usize) {
            let mut kind = [0u8; 16];
            kind.copy_from_slice(&entry[..16]);
            let which = match kind {
                RECORD_TYPE => 0,
                SLOT_A_TYPE => 1,
                SLOT_B_TYPE => 2,
                _ => continue,
            };
            if found[which].is_some() {
                return Err(Refusal::Missing);
            }
            let partition = Partition {
                first: word64(entry, 32),
                last: word64(entry, 40),
            };
            if partition.first > partition.last
                || partition.first < header.first_usable
                || partition.last > header.last_usable
            {
                return Err(Refusal::Range);
            }
            found[which] = Some(partition);
        }
        match found {
            [Some(record), Some(a), Some(b)] => Ok(Self { record, a, b }),
            _ => Err(Refusal::Missing),
        }
    }

    /// The partition holding `slot`.
    #[must_use]
    pub const fn slot(&self, slot: Slot) -> Partition {
        match slot {
            Slot::A => self.a,
            Slot::B => self.b,
        }
    }
}

/// Which slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Slot A.
    A,
    /// Slot B.
    B,
}

impl Slot {
    /// The other one.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    /// Its letter, for what the loader prints.
    #[must_use]
    pub const fn letter(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::A => b'A',
            Self::B => b'B',
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'A' => Some(Self::A),
            b'B' => Some(Self::B),
            _ => None,
        }
    }
}

/// `b"BHXSLOT1"`: the record's magic.
pub const RECORD_MAGIC: [u8; 8] = *b"BHXSLOT1";

/// The slot record: one block, the first of the record partition.
///
/// | bytes | field |
/// |---|---|
/// | 0..8 | `BHXSLOT1` |
/// | 8 | the active slot, `A` or `B` |
/// | 9 | the slot on trial, `A`, `B`, or 0 for none |
/// | 10 | boots the trial has left |
/// | 11..16 | zero |
/// | 16..24 | a count of writes, little-endian, so two copies can be told apart |
/// | 24..28 | CRC-32 of bytes 0..24 |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The slot that boots when nothing is on trial.
    pub active: Slot,
    /// The slot on trial, and how many boots it has left.
    pub trial: Option<(Slot, u8)>,
    /// How many times the record has been written.
    pub writes: u64,
}

impl Record {
    /// The block.
    #[must_use]
    pub fn to_block(&self) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[0..8].copy_from_slice(&RECORD_MAGIC);
        block[8] = self.active.byte();
        if let Some((slot, tries)) = self.trial {
            block[9] = slot.byte();
            block[10] = tries;
        }
        block[16..24].copy_from_slice(&self.writes.to_le_bytes());
        let crc = crc32(&block[0..24]);
        block[24..28].copy_from_slice(&crc.to_le_bytes());
        block
    }

    /// Reads the block back.
    ///
    /// # Errors
    ///
    /// [`Refusal::Record`] for a wrong magic, a wrong CRC, or a slot that is
    /// neither `A` nor `B`. A damaged record is not believed in part.
    pub fn parse(block: &[u8]) -> Result<Self, Refusal> {
        if block.len() < 28 {
            return Err(Refusal::Short);
        }
        if block[0..8] != RECORD_MAGIC || crc32(&block[0..24]) != word32(block, 24) {
            return Err(Refusal::Record);
        }
        let active = Slot::from_byte(block[8]).ok_or(Refusal::Record)?;
        let trial = match block[9] {
            0 => None,
            byte => Some((Slot::from_byte(byte).ok_or(Refusal::Record)?, block[10])),
        };
        Ok(Self {
            active,
            trial,
            writes: word64(block, 16),
        })
    }
}

/// What the loader does, decided from the record before anything is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The slot to try first.
    pub first: Slot,
    /// The slot to fall back to if the first does not read or verify.
    pub then: Slot,
    /// The record to write **before** booting, if any: the one block this
    /// loader writes.
    pub write: Option<Record>,
    /// Why, in a phrase the loader prints.
    pub why: Why,
}

/// Why the plan is what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The record could not be read or was damaged: A, then B, and nothing
    /// written -- a damaged record is not rewritten from a guess.
    NoRecord,
    /// Nothing on trial: the active slot.
    Active,
    /// A slot on trial with boots left: it, with one boot fewer recorded first.
    Trial {
        /// Boots it has left after this one.
        left: u8,
    },
    /// A trial with no boots left: it failed, the record says so, and the
    /// active slot boots.
    TrialOver,
}

/// The decision.
///
/// **The count goes down before the trial boots**, not after: a trial set that
/// hangs or resets the machine never gets to say it failed, so the only way its
/// boots can run out is for each to be spent on the way in.
#[must_use]
pub fn plan(record: Option<Record>) -> Plan {
    let Some(record) = record else {
        return Plan {
            first: Slot::A,
            then: Slot::B,
            write: None,
            why: Why::NoRecord,
        };
    };
    match record.trial {
        Some((slot, tries)) if tries > 0 => Plan {
            first: slot,
            then: record.active,
            write: Some(Record {
                trial: Some((slot, tries - 1)),
                writes: record.writes.wrapping_add(1),
                ..record
            }),
            why: Why::Trial { left: tries - 1 },
        },
        Some(_) => Plan {
            first: record.active,
            then: record.active.other(),
            write: Some(Record {
                trial: None,
                writes: record.writes.wrapping_add(1),
                ..record
            }),
            why: Why::TrialOver,
        },
        None => Plan {
            first: record.active,
            then: record.active.other(),
            write: None,
            why: Why::Active,
        },
    }
}

/// `b"BHXSET01"`: a slot's header magic.
pub const SET_MAGIC: [u8; 8] = *b"BHXSET01";

/// The four files of a boot set, in the order the header lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    /// The kernel.
    Kernel = 0,
    /// The initrd.
    Initrd = 1,
    /// `boot.conf`.
    Conf = 2,
    /// `boot.sig`.
    Sig = 3,
}

/// A slot's header: its first block, naming where each file lies.
///
/// | bytes | field |
/// |---|---|
/// | 0..8 | `BHXSET01` |
/// | 8 + 16 *n*.. | file *n*'s offset from the slot's start, then its length, each `u64` |
///
/// Offsets are block-aligned and lie after the header; every file lies wholly
/// inside the slot. Nothing here says the files are genuine: `boot.sig` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetHeader {
    /// Offset and length of each file, by [`File`].
    pub files: [(u64, u64); 4],
}

impl SetHeader {
    /// The block.
    #[must_use]
    pub fn to_block(&self) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[0..8].copy_from_slice(&SET_MAGIC);
        for (index, (offset, length)) in self.files.iter().enumerate() {
            block[8 + index * 16..16 + index * 16].copy_from_slice(&offset.to_le_bytes());
            block[16 + index * 16..24 + index * 16].copy_from_slice(&length.to_le_bytes());
        }
        block
    }

    /// Reads a slot's header, checking every file against `slot_bytes`, the
    /// slot's size.
    ///
    /// # Errors
    ///
    /// [`Refusal::SetHeader`] for a wrong magic, a file that is not
    /// block-aligned, overlaps the header, or runs past the slot.
    pub fn parse(block: &[u8], slot_bytes: u64) -> Result<Self, Refusal> {
        if block.len() < 72 {
            return Err(Refusal::Short);
        }
        if block[0..8] != SET_MAGIC {
            return Err(Refusal::SetHeader);
        }
        let mut files = [(0, 0); 4];
        for (index, file) in files.iter_mut().enumerate() {
            let offset = word64(block, 8 + index * 16);
            let length = word64(block, 16 + index * 16);
            let end = offset.checked_add(length).ok_or(Refusal::SetHeader)?;
            if offset < BLOCK as u64 || !offset.is_multiple_of(BLOCK as u64) || end > slot_bytes {
                return Err(Refusal::SetHeader);
            }
            *file = (offset, length);
        }
        Ok(Self { files })
    }

    /// Where `file` lies: its first block within the slot, and its length.
    #[must_use]
    pub const fn locate(&self, file: File) -> (u64, u64) {
        let (offset, length) = self.files[file as usize];
        (offset / BLOCK as u64, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot disk, built the way the build tool builds one.
    fn disk(record: Option<Record>) -> Vec<u8> {
        let blocks = 4096u64;
        let mut image = vec![0u8; blocks as usize * BLOCK];
        let parts = [
            (RECORD_TYPE, 64u64, 71u64),
            (SLOT_A_TYPE, 128, 1023),
            (SLOT_B_TYPE, 1024, 2047),
        ];
        let mut entries = vec![0u8; 128 * 128];
        for (index, (kind, first, last)) in parts.iter().enumerate() {
            let entry = &mut entries[index * 128..(index + 1) * 128];
            entry[..16].copy_from_slice(kind);
            entry[16] = index as u8 + 1;
            entry[32..40].copy_from_slice(&first.to_le_bytes());
            entry[40..48].copy_from_slice(&last.to_le_bytes());
        }
        let mut header = [0u8; 92];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        header[32..40].copy_from_slice(&(blocks - 1).to_le_bytes());
        header[40..48].copy_from_slice(&34u64.to_le_bytes());
        header[48..56].copy_from_slice(&(blocks - 34).to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        header[88..92].copy_from_slice(&crc32(&entries).to_le_bytes());
        let crc = crc32(&header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
        image[BLOCK..BLOCK + 92].copy_from_slice(&header);
        image[2 * BLOCK..2 * BLOCK + entries.len()].copy_from_slice(&entries);
        if let Some(record) = record {
            image[64 * BLOCK..65 * BLOCK].copy_from_slice(&record.to_block());
        }
        image
    }

    fn layout(image: &[u8]) -> Result<Layout, Refusal> {
        let header = Header::parse(&image[BLOCK..2 * BLOCK])?;
        let at = header.entries_at as usize * BLOCK;
        Layout::find(&header, &image[at..at + header.entries_bytes()])
    }

    #[test]
    fn the_crc_is_the_one_gpt_and_zlib_use() {
        // The standard check value, and an empty input.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_slot_disk_s_three_partitions_are_found_by_type() {
        let image = disk(None);
        let layout = layout(&image).unwrap();
        assert_eq!(
            layout.record,
            Partition {
                first: 64,
                last: 71
            }
        );
        assert_eq!(
            layout.slot(Slot::A),
            Partition {
                first: 128,
                last: 1023
            }
        );
        assert_eq!(layout.slot(Slot::B).bytes(), 1024 * BLOCK as u64);
    }

    #[test]
    fn a_damaged_header_or_entry_array_is_refused_by_name() {
        let good = disk(None);
        let mut image = good.clone();
        image[BLOCK + 40] ^= 1; // first usable, under the header CRC
        assert_eq!(layout(&image), Err(Refusal::HeaderCrc));
        let mut image = good.clone();
        image[2 * BLOCK + 32] ^= 1; // the record's first block, under the entries CRC
        assert_eq!(layout(&image), Err(Refusal::EntriesCrc));
        let mut image = good.clone();
        image[BLOCK] = b'X';
        assert_eq!(layout(&image), Err(Refusal::NotGpt));
        assert_eq!(Header::parse(&good[..100]), Err(Refusal::Short));
    }

    #[test]
    fn a_disk_missing_a_partition_is_not_a_slot_disk() {
        let mut image = disk(None);
        // Slot B's type changed, and both CRCs made right again.
        image[2 * BLOCK + 256] ^= 0xFF;
        let entries_crc = crc32(&image[2 * BLOCK..2 * BLOCK + 128 * 128]);
        image[BLOCK + 88..BLOCK + 92].copy_from_slice(&entries_crc.to_le_bytes());
        image[BLOCK + 16..BLOCK + 20].fill(0);
        let crc = crc32(&image[BLOCK..BLOCK + 92]);
        image[BLOCK + 16..BLOCK + 20].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(layout(&image), Err(Refusal::Missing));
    }

    #[test]
    fn a_record_round_trips_and_a_damaged_one_is_not_believed_in_part() {
        let record = Record {
            active: Slot::A,
            trial: Some((Slot::B, 2)),
            writes: 7,
        };
        let block = record.to_block();
        assert_eq!(Record::parse(&block), Ok(record));
        for at in 0..28 {
            let mut damaged = block;
            damaged[at] ^= 0x10;
            assert_eq!(Record::parse(&damaged), Err(Refusal::Record), "byte {at}");
        }
        assert_eq!(Record::parse(&[0u8; BLOCK]), Err(Refusal::Record));
    }

    #[test]
    fn a_trial_spends_a_boot_on_the_way_in_and_falls_back_when_none_are_left() {
        let mut record = Record {
            active: Slot::A,
            trial: Some((Slot::B, 2)),
            writes: 0,
        };
        let mut booted = Vec::new();
        for _ in 0..4 {
            let plan = plan(Some(record));
            booted.push(plan.first);
            if let Some(next) = plan.write {
                assert_eq!(next.writes, record.writes + 1, "every write is counted");
                record = next;
            }
        }
        assert_eq!(booted, [Slot::B, Slot::B, Slot::A, Slot::A]);
        assert_eq!(
            record.trial, None,
            "the trial is over, and the record says so"
        );
        assert_eq!(record.active, Slot::A);
    }

    #[test]
    fn every_plan_falls_back_to_the_other_slot_and_writes_only_for_a_trial() {
        assert_eq!(
            plan(None),
            Plan {
                first: Slot::A,
                then: Slot::B,
                write: None,
                why: Why::NoRecord
            }
        );
        let settled = Record {
            active: Slot::B,
            trial: None,
            writes: 3,
        };
        let plan = plan(Some(settled));
        assert_eq!(
            (plan.first, plan.then, plan.write),
            (Slot::B, Slot::A, None)
        );
    }

    #[test]
    fn a_slot_header_names_files_inside_its_slot_and_nothing_else() {
        let header = SetHeader {
            files: [(512, 4000), (4608, 10_000), (14_848, 20), (15_360, 7000)],
        };
        let block = header.to_block();
        assert_eq!(SetHeader::parse(&block, 1 << 20), Ok(header));
        assert_eq!(header.locate(File::Initrd), (9, 10_000));
        // Past the slot, unaligned, inside the header, overflowing: refused.
        assert_eq!(SetHeader::parse(&block, 20_000), Err(Refusal::SetHeader));
        for (index, offset, length) in [(0, 513u64, 1u64), (1, 0, 1), (2, 512, u64::MAX)] {
            let mut bad = header;
            bad.files[index] = (offset, length);
            assert_eq!(
                SetHeader::parse(&bad.to_block(), 1 << 20),
                Err(Refusal::SetHeader),
                "file {index}"
            );
        }
        let mut wrong = block;
        wrong[0] = b'X';
        assert_eq!(SetHeader::parse(&wrong, 1 << 20), Err(Refusal::SetHeader));
    }
}
