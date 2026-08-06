// SPDX-License-Identifier: Apache-2.0
//! The on-disk format, and the arithmetic over it.
//!
//! [RFC 0015](../../docs/rfc/0015-filesystem.md) step 2. Deliberately small: a
//! superblock, a bitmap of free blocks, inodes with direct and single-indirect
//! blocks, and directories as arrays of fixed entries. No extents, no B-trees,
//! no extended attributes.
//!
//! # Everything here is untrusted input
//!
//! A disk is bytes somebody else wrote, and a filesystem parser is what stands
//! between a corrupted one and the rest of the system. So nothing in this file
//! indexes without checking, nothing trusts a length it read, and the `unsafe`
//! budget is zero — the same standard `ustar` is held to, for the same reason.
//!
//! # No allocation, and no kernel
//!
//! Everything works over `&[u8]` or `&mut [u8]`. That is what lets the same
//! code build an image on a developer's machine, be tested on the host, and
//! run in a service in a domain with no heap under it.
#![no_std]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

/// How big a block is, everywhere.
///
/// One page. A filesystem block that is not a page means every cached block
/// either wastes memory or spans two, and the page cache RFC 0015 proposes
/// would inherit that choice for ever.
pub const BLOCK: usize = 4096;

/// Bytes an inode occupies on disk.
pub const INODE: usize = 64;

/// Bytes a directory entry occupies on disk.
pub const ENTRY: usize = 32;

/// The longest name this format can hold.
///
/// Twenty-seven, because an entry is thirty-two bytes and the rest is an inode
/// number and a length. Short, fixed, and checked — a name field that could be
/// longer than its entry is the first thing a corrupted directory would use.
pub const MAX_NAME: usize = 27;

/// What the first eight bytes of a filesystem say.
pub const MAGIC: u64 = u64::from_le_bytes(*b"BHASKIXF");

/// The version this code writes and reads.
pub const VERSION: u32 = 1;

/// What went wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsError {
    /// The bytes are not this filesystem, or are damaged.
    NotAFilesystem,
    /// A structure named something outside the image.
    OutOfRange,
    /// No free block, or no free inode.
    Full,
    /// The name is longer than this format can hold, or empty.
    BadName,
    /// No entry of that name.
    NotFound,
    /// A file operation on a directory, or the reverse.
    WrongKind,
}

/// What an inode is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Not in use.
    Free,
    /// A file.
    File,
    /// A directory.
    Directory,
}

impl Kind {
    /// As it is stored.
    #[must_use]
    pub const fn to_bits(self) -> u16 {
        match self {
            Self::Free => 0,
            Self::File => 1,
            Self::Directory => 2,
        }
    }

    /// From what was stored. Anything else is `Free`, because an inode whose
    /// kind is not one this code knows is an inode this code must not use —
    /// and treating it as free is the reading that cannot hand out a file.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        match bits {
            1 => Self::File,
            2 => Self::Directory,
            _ => Self::Free,
        }
    }
}

/// Reads a little-endian `u32` at `at`, or `None` if it does not fit.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(slice);
    Some(u32::from_le_bytes(buffer))
}

/// Reads a little-endian `u64` at `at`, or `None` if it does not fit.
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at.checked_add(8)?)?;
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(slice);
    Some(u64::from_le_bytes(buffer))
}

/// Reads a little-endian `u16` at `at`, or `None` if it does not fit.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Writes `value` at `at`, if it fits.
fn put(bytes: &mut [u8], at: usize, value: &[u8]) -> Option<()> {
    let end = at.checked_add(value.len())?;
    bytes.get_mut(at..end)?.copy_from_slice(value);
    Some(())
}

/// A checksum over bytes.
///
/// FNV-1a, folded to 32 bits. Not cryptographic and not meant to be: this
/// catches a disk that lied or a write that was torn, and both of those are
/// accidents. A journal commit that an attacker can forge is a different
/// problem and needs a different answer.
#[must_use]
pub fn checksum(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Never zero, so that a field somebody forgot to write is not a checksum
    // that happens to match a run of zeroes.
    if hash == 0 { 1 } else { hash }
}

/// Where everything is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Superblock {
    /// How many blocks the image has, in total.
    pub blocks: u64,
    /// How many inodes it has room for.
    pub inodes: u64,
    /// First block of the free-block bitmap.
    pub bitmap_start: u64,
    /// First block of the inode table.
    pub inode_start: u64,
    /// First block that holds data.
    pub data_start: u64,
    /// The inode the root directory is.
    pub root: u32,
}

impl Superblock {
    /// Bytes the superblock's checksum covers.
    const COVERED: usize = 60;

    /// Reads it, and refuses anything that does not describe itself.
    ///
    /// # Errors
    ///
    /// [`FsError::NotAFilesystem`] for a wrong magic, version or checksum, and
    /// [`FsError::OutOfRange`] for a layout whose regions do not fit inside the
    /// image or run backwards.
    pub fn read(bytes: &[u8]) -> Result<Self, FsError> {
        let head = bytes.get(..BLOCK).ok_or(FsError::NotAFilesystem)?;
        if u64_at(head, 0) != Some(MAGIC) || u32_at(head, 8) != Some(VERSION) {
            return Err(FsError::NotAFilesystem);
        }
        if u32_at(head, 12) != Some(BLOCK as u32) {
            return Err(FsError::NotAFilesystem);
        }

        let stored = u32_at(head, Self::COVERED).ok_or(FsError::NotAFilesystem)?;
        if stored != checksum(&head[..Self::COVERED]) {
            return Err(FsError::NotAFilesystem);
        }

        let found = Self {
            blocks: u64_at(head, 16).ok_or(FsError::NotAFilesystem)?,
            inodes: u64_at(head, 24).ok_or(FsError::NotAFilesystem)?,
            bitmap_start: u64_at(head, 32).ok_or(FsError::NotAFilesystem)?,
            inode_start: u64_at(head, 40).ok_or(FsError::NotAFilesystem)?,
            data_start: u64_at(head, 48).ok_or(FsError::NotAFilesystem)?,
            root: u32_at(head, 56).ok_or(FsError::NotAFilesystem)?,
        };

        // The checksum says the bytes are the ones that were written. It says
        // nothing about whether they describe a filesystem that can exist, and
        // every field below is used as an index later.
        if found.blocks == 0
            || found.bitmap_start == 0
            || found.inode_start <= found.bitmap_start
            || found.data_start <= found.inode_start
            || found.data_start >= found.blocks
            || found.blocks > (bytes.len() / BLOCK) as u64
            || u64::from(found.root) >= found.inodes
        {
            return Err(FsError::OutOfRange);
        }
        Ok(found)
    }

    /// Writes it, checksum and all.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] if the image is smaller than one block.
    pub fn write(&self, bytes: &mut [u8]) -> Result<(), FsError> {
        let head = bytes.get_mut(..BLOCK).ok_or(FsError::OutOfRange)?;
        head.fill(0);
        put(head, 0, &MAGIC.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 8, &VERSION.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 12, &(BLOCK as u32).to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 16, &self.blocks.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 24, &self.inodes.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 32, &self.bitmap_start.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 40, &self.inode_start.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 48, &self.data_start.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(head, 56, &self.root.to_le_bytes()).ok_or(FsError::OutOfRange)?;

        let sum = checksum(&head[..Self::COVERED]);
        put(head, Self::COVERED, &sum.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        Ok(())
    }
}

/// One file or directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Inode {
    /// What it is.
    pub kind: Kind,
    /// How many directory entries name it.
    pub links: u16,
    /// Bumped every time this slot is reused.
    ///
    /// RFC 0015's decision: a `Directory` capability names an inode *and* a
    /// generation, so a capability that outlived its directory resolves to
    /// nothing rather than to whatever took the slot. The same shape
    /// `MemoryId` and `NotificationId` already have.
    pub generation: u32,
    /// Bytes, for a file. Entries times [`ENTRY`], for a directory.
    pub size: u64,
    /// Blocks this inode owns, in order.
    pub direct: [u32; 10],
    /// A block holding more block numbers, or zero.
    pub indirect: u32,
}

impl Inode {
    /// Bytes the inode's checksum covers.
    const COVERED: usize = 60;

    /// Reads inode `index` out of the table.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] if the table does not reach that far, and
    /// [`FsError::NotAFilesystem`] if the inode's checksum does not match.
    pub fn read(bytes: &[u8], superblock: &Superblock, index: u32) -> Result<Self, FsError> {
        if u64::from(index) >= superblock.inodes {
            return Err(FsError::OutOfRange);
        }
        let at = superblock
            .inode_start
            .checked_mul(BLOCK as u64)
            .and_then(|start| start.checked_add(u64::from(index) * INODE as u64))
            .and_then(|at| usize::try_from(at).ok())
            .ok_or(FsError::OutOfRange)?;
        let slot = bytes
            .get(at..at.checked_add(INODE).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)?;

        let stored = u32_at(slot, Self::COVERED).ok_or(FsError::OutOfRange)?;
        if stored == 0 {
            // Never written. `checksum` never returns zero, precisely so that
            // a zeroed slot is unambiguous: a fresh inode table is zeroes, and
            // writing a valid "free" inode into every slot at format time
            // would be a megabyte of writes to say what the zeroes already
            // say.
            //
            // Corruption that zeroes only this field therefore reads as free
            // rather than as damaged, which loses a file rather than exposing
            // one — the direction to fail in.
            return Ok(Self {
                kind: Kind::Free,
                links: 0,
                generation: 0,
                size: 0,
                direct: [0; 10],
                indirect: 0,
            });
        }
        if stored != checksum(&slot[..Self::COVERED]) {
            return Err(FsError::NotAFilesystem);
        }

        let mut direct = [0u32; 10];
        for (which, block) in direct.iter_mut().enumerate() {
            *block = u32_at(slot, 16 + which * 4).ok_or(FsError::OutOfRange)?;
        }

        Ok(Self {
            kind: Kind::from_bits(u16_at(slot, 0).ok_or(FsError::OutOfRange)?),
            links: u16_at(slot, 2).ok_or(FsError::OutOfRange)?,
            generation: u32_at(slot, 4).ok_or(FsError::OutOfRange)?,
            size: u64_at(slot, 8).ok_or(FsError::OutOfRange)?,
            direct,
            indirect: u32_at(slot, 56).ok_or(FsError::OutOfRange)?,
        })
    }

    /// Writes inode `index` into the table.
    ///
    /// # Errors
    ///
    /// As [`Inode::read`].
    pub fn write(
        &self,
        bytes: &mut [u8],
        superblock: &Superblock,
        index: u32,
    ) -> Result<(), FsError> {
        if u64::from(index) >= superblock.inodes {
            return Err(FsError::OutOfRange);
        }
        let at = superblock
            .inode_start
            .checked_mul(BLOCK as u64)
            .and_then(|start| start.checked_add(u64::from(index) * INODE as u64))
            .and_then(|at| usize::try_from(at).ok())
            .ok_or(FsError::OutOfRange)?;
        let end = at.checked_add(INODE).ok_or(FsError::OutOfRange)?;
        let slot = bytes.get_mut(at..end).ok_or(FsError::OutOfRange)?;

        slot.fill(0);
        put(slot, 0, &self.kind.to_bits().to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(slot, 2, &self.links.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(slot, 4, &self.generation.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(slot, 8, &self.size.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        for (which, block) in self.direct.iter().enumerate() {
            put(slot, 16 + which * 4, &block.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        }
        put(slot, 56, &self.indirect.to_le_bytes()).ok_or(FsError::OutOfRange)?;

        let sum = checksum(&slot[..Self::COVERED]);
        put(slot, Self::COVERED, &sum.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        Ok(())
    }
}

/// Which blocks are in use.
///
/// One bit per block, block zero first. A set bit is a block somebody owns.
pub struct Bitmap<'a> {
    bytes: &'a mut [u8],
    blocks: u64,
    first_data: u64,
}

impl<'a> Bitmap<'a> {
    /// Finds the bitmap inside an image.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] if the image does not hold the region the
    /// superblock describes.
    pub fn of(bytes: &'a mut [u8], superblock: &Superblock) -> Result<Self, FsError> {
        let start = usize::try_from(superblock.bitmap_start * BLOCK as u64)
            .map_err(|_| FsError::OutOfRange)?;
        let length =
            usize::try_from((superblock.inode_start - superblock.bitmap_start) * BLOCK as u64)
                .map_err(|_| FsError::OutOfRange)?;
        let end = start.checked_add(length).ok_or(FsError::OutOfRange)?;
        // The bitmap must be able to describe every block, or a block near the
        // end has no bit and could be handed out twice.
        if (length * 8) < usize::try_from(superblock.blocks).map_err(|_| FsError::OutOfRange)? {
            return Err(FsError::OutOfRange);
        }
        Ok(Self {
            bytes: bytes.get_mut(start..end).ok_or(FsError::OutOfRange)?,
            blocks: superblock.blocks,
            first_data: superblock.data_start,
        })
    }

    /// Whether `block` is in use.
    #[must_use]
    pub fn used(&self, block: u64) -> bool {
        let Ok(index) = usize::try_from(block / 8) else {
            return true;
        };
        self.bytes
            .get(index)
            .is_some_and(|byte| byte & (1 << (block % 8)) != 0)
    }

    fn set(&mut self, block: u64, used: bool) {
        let Ok(index) = usize::try_from(block / 8) else {
            return;
        };
        if let Some(byte) = self.bytes.get_mut(index) {
            let bit = 1 << (block % 8);
            if used {
                *byte |= bit;
            } else {
                *byte &= !bit;
            }
        }
    }

    /// Takes the first free data block.
    ///
    /// Never returns a block before `data_start`: the superblock, the bitmap
    /// and the inode table are not data, and an allocator that could hand one
    /// out would let a file overwrite the map that finds it.
    ///
    /// # Errors
    ///
    /// [`FsError::Full`] when there is none.
    pub fn allocate(&mut self) -> Result<u64, FsError> {
        for block in self.first_data..self.blocks {
            if !self.used(block) {
                self.set(block, true);
                return Ok(block);
            }
        }
        Err(FsError::Full)
    }

    /// Gives a block back.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] for a block that is not data — freeing the
    /// inode table is not something a caller should be able to ask for by
    /// getting a number wrong.
    pub fn free(&mut self, block: u64) -> Result<(), FsError> {
        if block < self.first_data || block >= self.blocks {
            return Err(FsError::OutOfRange);
        }
        self.set(block, false);
        Ok(())
    }

    /// How many data blocks are in use.
    #[must_use]
    pub fn in_use(&self) -> u64 {
        (self.first_data..self.blocks)
            .filter(|block| self.used(*block))
            .count() as u64
    }
}

/// One entry of a directory, as it is stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    /// Which inode.
    pub inode: u32,
    /// Its name, as bytes.
    pub name: [u8; MAX_NAME],
    /// How many of those bytes are the name.
    pub length: u8,
}

impl Entry {
    /// Builds one.
    ///
    /// # Errors
    ///
    /// [`FsError::BadName`] for a name that is empty, too long, or contains a
    /// separator or a NUL — all three of which would make a name that resolves
    /// to something other than itself.
    pub fn new(inode: u32, name: &[u8]) -> Result<Self, FsError> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(FsError::BadName);
        }
        if name.iter().any(|byte| *byte == b'/' || *byte == 0) {
            return Err(FsError::BadName);
        }
        let mut stored = [0u8; MAX_NAME];
        stored[..name.len()].copy_from_slice(name);
        Ok(Self {
            inode,
            name: stored,
            length: name.len() as u8,
        })
    }

    /// The name, without the padding.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        let length = (self.length as usize).min(MAX_NAME);
        &self.name[..length]
    }

    /// Reads one out of a block.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] if the block does not reach that far.
    pub fn read(bytes: &[u8], at: usize) -> Result<Self, FsError> {
        let slot = bytes
            .get(at..at.checked_add(ENTRY).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)?;
        let mut name = [0u8; MAX_NAME];
        name.copy_from_slice(slot.get(5..5 + MAX_NAME).ok_or(FsError::OutOfRange)?);
        Ok(Self {
            inode: u32_at(slot, 0).ok_or(FsError::OutOfRange)?,
            // Clamped on the way in, so a corrupted length cannot make `name`
            // read past the entry it is stored in.
            length: (*slot.get(4).ok_or(FsError::OutOfRange)?).min(MAX_NAME as u8),
            name,
        })
    }

    /// Writes one into a block.
    ///
    /// # Errors
    ///
    /// As [`Entry::read`].
    pub fn write(&self, bytes: &mut [u8], at: usize) -> Result<(), FsError> {
        let end = at.checked_add(ENTRY).ok_or(FsError::OutOfRange)?;
        let slot = bytes.get_mut(at..end).ok_or(FsError::OutOfRange)?;
        slot.fill(0);
        put(slot, 0, &self.inode.to_le_bytes()).ok_or(FsError::OutOfRange)?;
        put(slot, 4, &[self.length]).ok_or(FsError::OutOfRange)?;
        put(slot, 5, &self.name).ok_or(FsError::OutOfRange)?;
        Ok(())
    }
}

/// Lays out a fresh filesystem over `bytes`.
///
/// Returns the superblock it wrote. The image is zeroed first, so a builder
/// that ran over an old image leaves nothing of it behind.
///
/// # Errors
///
/// [`FsError::OutOfRange`] if the image is too small to hold a superblock, a
/// bitmap, an inode table and at least one data block.
pub fn format(bytes: &mut [u8], inodes: u64) -> Result<Superblock, FsError> {
    let blocks = (bytes.len() / BLOCK) as u64;
    if blocks < 4 || inodes == 0 {
        return Err(FsError::OutOfRange);
    }
    bytes.fill(0);

    // One bitmap block covers 32,768 blocks, which is 128 MiB.
    let bitmap_blocks = blocks.div_ceil(BLOCK as u64 * 8).max(1);
    let inode_blocks = (inodes * INODE as u64).div_ceil(BLOCK as u64).max(1);

    let superblock = Superblock {
        blocks,
        inodes,
        bitmap_start: 1,
        inode_start: 1 + bitmap_blocks,
        data_start: 1 + bitmap_blocks + inode_blocks,
        root: 0,
    };
    if superblock.data_start >= blocks {
        return Err(FsError::OutOfRange);
    }
    superblock.write(bytes)?;

    // Everything up to the first data block is in use, and is marked so before
    // anything can allocate: a bitmap that starts empty is a bitmap that hands
    // out the superblock.
    {
        let mut bitmap = Bitmap::of(bytes, &superblock)?;
        for block in 0..superblock.data_start {
            bitmap.set(block, true);
        }
    }

    // The root, which is a directory with no entries. Its generation starts at
    // one so that zero is never a live generation — a capability built out of
    // a zeroed page names nothing.
    let root = Inode {
        kind: Kind::Directory,
        links: 1,
        generation: 1,
        size: 0,
        direct: [0; 10],
        indirect: 0,
    };
    root.write(bytes, &superblock, superblock.root)?;
    Ok(superblock)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::{BLOCK, Bitmap, ENTRY, Entry, FsError, Inode, Kind, Superblock, format};

    fn image(blocks: usize) -> Vec<u8> {
        vec![0u8; blocks * BLOCK]
    }

    #[test]
    fn a_fresh_filesystem_describes_itself() {
        let mut bytes = image(64);
        let written = format(&mut bytes, 128).expect("a filesystem fits in 64 blocks");
        let read = Superblock::read(&bytes).expect("and reads back");
        assert_eq!(written, read);

        let root = Inode::read(&bytes, &read, read.root).expect("the root exists");
        assert_eq!(root.kind, Kind::Directory);
        assert_eq!(root.generation, 1, "zero is never a live generation");
    }

    #[test]
    fn an_inode_round_trips_every_field() {
        let mut bytes = image(64);
        let superblock = format(&mut bytes, 128).unwrap();

        let written = Inode {
            kind: Kind::File,
            links: 3,
            generation: 0x1234_5678,
            size: 0x9abc_def0_1234,
            direct: [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            indirect: 99,
        };
        written.write(&mut bytes, &superblock, 7).unwrap();
        assert_eq!(Inode::read(&bytes, &superblock, 7).unwrap(), written);

        // And the neighbours were not touched, which is what a fixed-size slot
        // is for and the sort of thing an off-by-one in the offset would break
        // without changing the value that was written.
        assert_eq!(
            Inode::read(&bytes, &superblock, 6).unwrap().kind,
            Kind::Free
        );
        assert_eq!(
            Inode::read(&bytes, &superblock, 8).unwrap().kind,
            Kind::Free
        );
    }

    #[test]
    fn the_allocator_never_hands_out_the_same_block_twice() {
        let mut bytes = image(64);
        let superblock = format(&mut bytes, 128).unwrap();
        let mut bitmap = Bitmap::of(&mut bytes, &superblock).unwrap();

        // Every bit cleared first, including the metadata's. `format` marks
        // those in use, so with them set this test passed even when the
        // allocator was allowed to consider block zero -- two guards again,
        // and the bitmap was doing all the work. Cleared, only the allocator's
        // own floor stands between a file and the superblock.
        // Through `set` and not `free`, because `free` refuses a metadata
        // block -- which is the second guard, and the one being taken away.
        for block in 0..superblock.blocks {
            bitmap.set(block, false);
        }
        for block in 0..superblock.data_start {
            assert!(
                !bitmap.used(block),
                "cleared, so the floor is the only guard"
            );
        }

        let mut seen = Vec::new();
        while let Ok(block) = bitmap.allocate() {
            assert!(!seen.contains(&block), "block {block} handed out twice");
            assert!(
                block >= superblock.data_start,
                "a data block, never the map that finds it"
            );
            seen.push(block);
        }
        assert_eq!(seen.len() as u64, superblock.blocks - superblock.data_start);
        assert_eq!(bitmap.allocate(), Err(FsError::Full), "and then it says so");
    }

    #[test]
    fn a_freed_block_comes_back_and_the_metadata_cannot_be_freed() {
        let mut bytes = image(64);
        let superblock = format(&mut bytes, 128).unwrap();
        let mut bitmap = Bitmap::of(&mut bytes, &superblock).unwrap();

        let first = bitmap.allocate().unwrap();
        let second = bitmap.allocate().unwrap();
        assert_ne!(first, second);
        bitmap.free(first).unwrap();
        assert_eq!(bitmap.allocate(), Ok(first), "the freed one, first");

        // Freeing the superblock is not something a caller should be able to
        // ask for by getting a number wrong.
        assert_eq!(bitmap.free(0), Err(FsError::OutOfRange));
        assert_eq!(bitmap.free(superblock.blocks), Err(FsError::OutOfRange));
        assert!(bitmap.used(0), "and it is still in use");
    }

    #[test]
    fn a_name_that_would_resolve_to_something_else_is_refused() {
        assert!(Entry::new(1, b"hello").is_ok());
        assert_eq!(Entry::new(1, b"").unwrap_err(), FsError::BadName);
        assert_eq!(
            Entry::new(1, b"this name is far too long to fit in an entry").unwrap_err(),
            FsError::BadName
        );
        assert_eq!(Entry::new(1, b"a/b").unwrap_err(), FsError::BadName);
        assert_eq!(Entry::new(1, b"a\0b").unwrap_err(), FsError::BadName);
    }

    #[test]
    fn a_corrupted_length_cannot_make_a_name_leave_its_entry() {
        let mut block = vec![0u8; BLOCK];
        Entry::new(5, b"hello")
            .unwrap()
            .write(&mut block, 0)
            .unwrap();

        // A length nobody would write, of the sort a damaged disk supplies.
        block[4] = 0xff;
        let read = Entry::read(&block, 0).unwrap();

        // The *stored field*, not what `name()` returns. `name()` clamps too,
        // and asserting on it passed with this clamp removed -- two guards, and
        // a test that could not tell which of them was doing the work. This
        // one fails if `read` stops clamping, which is what it claims to check.
        assert_eq!(
            read.length as usize,
            super::MAX_NAME,
            "clamped on the way in"
        );
        assert_eq!(read.name().len(), super::MAX_NAME);
    }

    #[test]
    fn a_superblock_that_is_wrong_about_itself_is_refused() {
        let mut bytes = image(64);
        format(&mut bytes, 128).unwrap();

        let mut broken = bytes.clone();
        broken[0] = b'X';
        assert_eq!(
            Superblock::read(&broken).unwrap_err(),
            FsError::NotAFilesystem
        );

        let mut broken = bytes.clone();
        broken[16] = broken[16].wrapping_add(1); // blocks, without fixing the checksum
        assert_eq!(
            Superblock::read(&broken).unwrap_err(),
            FsError::NotAFilesystem
        );

        // Layouts that are internally consistent and impossible, each
        // checksummed correctly so that only its own range check can catch it.
        // One case per clause, because a single case passed while three of the
        // four clauses were removed: it was caught by whichever ran first, and
        // the test could not say which.
        let sound = Superblock {
            blocks: 64,
            inodes: 128,
            bitmap_start: 1,
            inode_start: 2,
            data_start: 3,
            root: 0,
        };
        for (what, wrong) in [
            ("no blocks at all", Superblock { blocks: 0, ..sound }),
            (
                "a bitmap at block zero, on top of the superblock",
                Superblock {
                    bitmap_start: 0,
                    ..sound
                },
            ),
            (
                "inodes before the bitmap",
                Superblock {
                    inode_start: 1,
                    ..sound
                },
            ),
            (
                "data before the inodes",
                Superblock {
                    data_start: 2,
                    ..sound
                },
            ),
            (
                "data past the end of the image",
                Superblock {
                    data_start: 64,
                    ..sound
                },
            ),
            (
                "a root outside the inode table",
                Superblock { root: 128, ..sound },
            ),
        ] {
            let mut broken = bytes.clone();
            wrong.write(&mut broken).unwrap();
            assert_eq!(
                Superblock::read(&broken).unwrap_err(),
                FsError::OutOfRange,
                "{what}"
            );
        }
    }

    #[test]
    fn no_single_byte_corruption_makes_the_parser_panic() {
        // The standard `ustar` is held to, for the same reason: a disk is
        // bytes somebody else wrote, and this parser is what stands between a
        // corrupted one and the rest of the system. Every byte of the
        // metadata, flipped one at a time -- the whole image would be slow and
        // the data blocks are not parsed.
        let mut bytes = image(16);
        let superblock = format(&mut bytes, 64).unwrap();
        let metadata = usize::try_from(superblock.data_start).unwrap() * BLOCK;

        for at in 0..metadata {
            for bit in 0..8 {
                let mut broken = bytes.clone();
                broken[at] ^= 1 << bit;

                // Whatever it says, it must not panic, and anything it hands
                // back must be usable without one either.
                if let Ok(found) = Superblock::read(&broken) {
                    for index in 0..found.inodes.min(64) as u32 {
                        if let Ok(inode) = Inode::read(&broken, &found, index) {
                            let _ = inode.size;
                            let _ = inode.direct;
                        }
                    }
                    if let Ok(bitmap) = Bitmap::of(&mut broken, &found) {
                        let _ = bitmap.in_use();
                    }
                }
            }
        }
    }

    #[test]
    fn an_entry_round_trips_through_a_block() {
        let mut block = vec![0u8; BLOCK];
        for slot in 0..4 {
            let entry = Entry::new(slot as u32 + 1, b"name").unwrap();
            entry.write(&mut block, slot * ENTRY).unwrap();
        }
        for slot in 0..4 {
            let read = Entry::read(&block, slot * ENTRY).unwrap();
            assert_eq!(read.inode, slot as u32 + 1);
            assert_eq!(read.name(), b"name");
        }
    }
}
