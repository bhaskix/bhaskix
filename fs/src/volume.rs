// SPDX-License-Identifier: Apache-2.0
//! Writing to a filesystem, through the journal: RFC 0015 step 5.
//!
//! Everything that changes the filesystem goes through [`Volume`], and every
//! block it writes goes through one function — [`Volume::put`] — which asks a
//! [`Watch`] first. That is the whole of the interruption harness: a `Watch`
//! that says "no" after the Nth write leaves the image in exactly the state a
//! machine losing power at that instant would leave it in, and the test then
//! mounts it and asks what survived.
//!
//! Routing every write through one place is not tidiness. It is what makes the
//! harness *complete*: a write that went round it would be a write the harness
//! cannot stop at, and the interruption it protects against would be the one
//! nobody tested.
//!
//! A transaction is prepared **in the journal's own payload blocks**. Staging
//! copies a block there, the change is made to that copy, and only the commit
//! block being written makes any of it real. There is no scratch buffer, which
//! matters in a kernel: eight spare blocks is thirty-two kilobytes of stack
//! that does not exist.
//!
//! **One thing goes round `put`, and saying so precisely matters more than the
//! tidier claim.** Preparing a staged block writes into the payload area
//! directly, without announcing it. It does not need announcing, because the
//! payload area means nothing until a commit block points at it — but it does
//! mean this harness cannot produce a *torn payload under a valid commit*, and
//! that is the one interruption it cannot reach. That case is covered instead
//! by `a_log_that_does_not_add_up_is_not_replayed`, which damages a payload
//! byte directly and requires the commit to be ignored, and it is the reason
//! the checksum covers the logged blocks rather than the header alone.
//!
//! The ordering itself — payload, then commit, then homes, then clear — is
//! checked by `a_transaction_has_exactly_one_shape`, which asserts the whole
//! sequence of writes. A weaker version of that test passed while the commit
//! was moved to the front, because the image came out byte-identical: the
//! payload is prepared in place, so those writes put no new bytes anywhere and
//! only the order they are *issued* in distinguishes the two. On a real disk
//! that order is the entire difference.

use crate::{
    BLOCK, ENTRY, Entry, FsError, INODE, Inode, Kind, Superblock, journal, journal::MAX_STAGED,
};

/// Asked before every block write.
///
/// The crash model, and it is deliberately the crudest one that is true:
/// writes reach the disk in the order they were issued, and at some point they
/// stop. Weaker models exist and matter — a device may reorder within a
/// barrier — and the reordering test covers that separately by permuting the
/// order the writes are *issued* in, which needs no extra machinery here.
pub trait Watch {
    /// `false` stops the operation before `block` is written.
    fn writing(&mut self, block: u32) -> bool;
}

impl<W: Watch + ?Sized> Watch for &mut W {
    fn writing(&mut self, block: u32) -> bool {
        (**self).writing(block)
    }
}

/// A `Watch` that never interrupts anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Uninterrupted;

impl Watch for Uninterrupted {
    fn writing(&mut self, _block: u32) -> bool {
        true
    }
}

/// Stops after a given number of writes have gone through.
///
/// `StopAfter::new(0)` interrupts before the first write, which is a case
/// worth having: it is the machine that died having done nothing, and a
/// recovery that needs at least one write to have happened would pass every
/// other N and fail this one.
#[derive(Clone, Copy, Debug)]
pub struct StopAfter {
    limit: u32,
    seen: u32,
}

impl StopAfter {
    /// Allows `limit` writes and then stops.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self { limit, seen: 0 }
    }

    /// How many writes went through.
    #[must_use]
    pub const fn writes(&self) -> u32 {
        self.seen
    }
}

impl Watch for StopAfter {
    fn writing(&mut self, _block: u32) -> bool {
        if self.seen >= self.limit {
            return false;
        }
        self.seen += 1;
        true
    }
}

/// Counts writes without stopping any, to find out how many there are.
#[derive(Clone, Copy, Debug, Default)]
pub struct Count(pub u32);

impl Watch for Count {
    fn writing(&mut self, _block: u32) -> bool {
        self.0 += 1;
        true
    }
}

/// A filesystem that can be written to.
///
/// Mounting one **recovers** it: there is no way to obtain a `Volume` whose
/// journal has not been replayed, because every way of getting one goes
/// through [`Volume::mount`]. A separate `recover()` a caller could forget to
/// call is the shape of this that has a bug in it.
pub struct Volume<'a> {
    bytes: &'a mut [u8],
    superblock: Superblock,
    sequence: u64,
    staged: [u32; MAX_STAGED],
    count: usize,
}

impl<'a> Volume<'a> {
    /// Mounts `bytes`, replaying any committed transaction first.
    ///
    /// Returns the volume and how many blocks the replay wrote — zero on a
    /// filesystem that was unmounted cleanly, which is the number the tests
    /// assert on to tell "recovered" from "there was nothing to recover".
    ///
    /// # Errors
    ///
    /// As [`Superblock::read`], and [`FsError::Interrupted`] if `watch`
    /// stopped the replay.
    pub fn mount(
        bytes: &'a mut [u8],
        watch: &mut (impl Watch + ?Sized),
    ) -> Result<(Self, u32), FsError> {
        let superblock = Superblock::read(bytes)?;
        let mut volume = Self {
            bytes,
            superblock,
            sequence: 0,
            staged: [0; MAX_STAGED],
            count: 0,
        };
        let replayed = volume.recover(watch)?;
        Ok((volume, replayed))
    }

    /// What the superblock says.
    #[must_use]
    pub const fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// The image, for a reader.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Replays a committed transaction, if there is one, and clears it.
    fn recover(&mut self, watch: &mut (impl Watch + ?Sized)) -> Result<u32, FsError> {
        let Some(commit) = journal::committed(self.bytes, &self.superblock) else {
            // Nothing committed. The payload blocks may hold anything -- a
            // transaction that was being prepared when the machine stopped --
            // and it is all ignored, because what makes a transaction real is
            // the commit block and nothing else.
            return Ok(0);
        };

        self.sequence = commit.sequence;
        for index in 0..commit.count {
            let (home, contents) = journal::logged(self.bytes, &self.superblock, index)?;
            self.put(home, &contents, watch)?;
        }

        // Cleared last, and an interruption here costs only another replay:
        // every write above puts the same bytes in the same places however
        // many times it runs, which is what lets this be a single ordering
        // rather than a protocol.
        self.clear_commit(watch)?;
        Ok(commit.count)
    }

    /// Writes one block. **The only place this crate writes to the image.**
    fn put(
        &mut self,
        block: u32,
        from: &[u8],
        watch: &mut (impl Watch + ?Sized),
    ) -> Result<(), FsError> {
        if u64::from(block) >= self.superblock.blocks {
            return Err(FsError::OutOfRange);
        }
        if !watch.writing(block) {
            return Err(FsError::Interrupted);
        }
        let at = (block as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        let end = at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?;
        let into = self.bytes.get_mut(at..end).ok_or(FsError::OutOfRange)?;
        let from = from.get(..BLOCK).ok_or(FsError::OutOfRange)?;
        into.copy_from_slice(from);
        Ok(())
    }

    /// Zeroes the commit block, so that nothing is pending.
    fn clear_commit(&mut self, watch: &mut (impl Watch + ?Sized)) -> Result<(), FsError> {
        let empty = [0u8; BLOCK];
        let block =
            u32::try_from(self.superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
        self.put(block, &empty, watch)
    }

    /// One block of the image.
    fn block(&self, index: u32) -> Result<&[u8], FsError> {
        let at = (index as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        self.bytes
            .get(at..at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)
    }

    /// Begins a transaction, discarding whatever the last one staged.
    ///
    /// Refuses outright if a transaction is still committed and unapplied.
    /// Staging writes into the journal's payload blocks, so preparing a new
    /// transaction over a pending one destroys it: the commit block still
    /// describes the old payload, its checksum no longer matches, and a
    /// transaction that was **acknowledged** quietly stops existing.
    ///
    /// A crash cannot reach this — the machine is gone and nothing else runs —
    /// but an interruption that is survivable can, and so can any future
    /// caller that keeps using a volume after an error. The invariant is
    /// therefore stated rather than argued: this volume never prepares a
    /// transaction while one is committed, and the way to clear one is to
    /// mount, which is the only thing that replays.
    ///
    /// # Errors
    ///
    /// [`FsError::NeedsRecovery`] if a committed transaction is pending.
    fn begin(&mut self) -> Result<(), FsError> {
        if journal::committed(self.bytes, &self.superblock).is_some() {
            return Err(FsError::NeedsRecovery);
        }
        self.count = 0;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        Ok(())
    }

    /// Copies `home` into the journal's payload, to be changed there.
    ///
    /// Returns the slot. Staging a block twice returns the slot it is already
    /// in rather than a second copy — two slots naming one home would apply in
    /// an order nobody chose, and the later one would silently undo the
    /// earlier. That is the bug this returns early to avoid.
    fn stage(&mut self, home: u32) -> Result<usize, FsError> {
        if let Some(slot) = self.staged[..self.count].iter().position(|at| *at == home) {
            return Ok(slot);
        }
        if self.count == MAX_STAGED {
            return Err(FsError::Full);
        }

        let slot = self.count;
        let source = (home as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        let destination = usize::try_from(self.superblock.journal_start + 1 + slot as u64)
            .ok()
            .and_then(|block| block.checked_mul(BLOCK))
            .ok_or(FsError::OutOfRange)?;
        if source.max(destination).checked_add(BLOCK) > Some(self.bytes.len()) {
            return Err(FsError::OutOfRange);
        }
        self.bytes.copy_within(source..source + BLOCK, destination);
        self.staged[slot] = home;
        self.count = slot + 1;
        Ok(slot)
    }

    /// The staged copy of a block, to be changed before it is committed.
    fn staged_mut(&mut self, slot: usize) -> Result<&mut [u8], FsError> {
        let at = usize::try_from(self.superblock.journal_start + 1 + slot as u64)
            .ok()
            .and_then(|block| block.checked_mul(BLOCK))
            .ok_or(FsError::OutOfRange)?;
        self.bytes
            .get_mut(at..at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)
    }

    /// Writes the payload, commits, applies, and clears.
    ///
    /// `order` permutes the writes *within* each phase — the payload writes
    /// among themselves and the home writes among themselves. It does not move
    /// a write across the commit, because that is the one ordering the journal
    /// depends on and a device that broke it would break every journal. What a
    /// device is entitled to reorder, this reorders.
    fn commit(
        &mut self,
        watch: &mut (impl Watch + ?Sized),
        order: &[usize],
    ) -> Result<(), FsError> {
        if self.count == 0 {
            return Ok(());
        }
        let order: &[usize] = if order.len() == self.count {
            order
        } else {
            &[0, 1, 2, 3, 4, 5, 6, 7][..self.count]
        };

        // 1. The payload is already in the journal blocks -- staging put it
        //    there. These are the writes of it, in whatever order.
        for slot in order {
            let block = u32::try_from(self.superblock.journal_start + 1 + *slot as u64)
                .map_err(|_| FsError::OutOfRange)?;
            if !watch.writing(block) {
                return Err(FsError::Interrupted);
            }
        }

        // 2. The commit. Everything before this instant is provisional and
        //    everything after it is certain, and that is the only claim this
        //    filesystem makes about durability.
        let head = journal::write_commit(
            self.bytes,
            &self.superblock,
            self.sequence,
            &self.staged[..self.count],
        )?;
        let commit_block =
            u32::try_from(self.superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
        self.put(commit_block, &head, watch)?;

        // 3. Home. Interrupted here, the commit stands and the next mount
        //    finishes it.
        for slot in order {
            let home = self.staged[*slot];
            let mut contents = [0u8; BLOCK];
            contents.copy_from_slice(self.staged_mut(*slot)?);
            self.put(home, &contents, watch)?;
        }

        // 4. Done, so the log is empty again.
        self.clear_commit(watch)?;
        self.count = 0;
        Ok(())
    }

    /// Where inode `index` lives: its block, and its offset within it.
    fn inode_at(&self, index: u32) -> Result<(u32, usize), FsError> {
        if u64::from(index) >= self.superblock.inodes {
            return Err(FsError::OutOfRange);
        }
        let byte = self
            .superblock
            .inode_start
            .checked_mul(BLOCK as u64)
            .and_then(|start| start.checked_add(u64::from(index) * INODE as u64))
            .ok_or(FsError::OutOfRange)?;
        let block = u32::try_from(byte / BLOCK as u64).map_err(|_| FsError::OutOfRange)?;
        Ok((block, (byte % BLOCK as u64) as usize))
    }

    /// Reads one inode out of the image as it stands.
    ///
    /// # Errors
    ///
    /// As [`Inode::read`].
    pub fn inode(&self, index: u32) -> Result<Inode, FsError> {
        Inode::read(self.bytes, &self.superblock, index)
    }

    /// Puts `inode` into the transaction being built.
    fn stage_inode(&mut self, index: u32, inode: &Inode) -> Result<(), FsError> {
        let (block, offset) = self.inode_at(index)?;
        let slot = self.stage(block)?;
        let staged = self.staged_mut(slot)?;
        inode.encode(
            staged
                .get_mut(offset..offset + INODE)
                .ok_or(FsError::OutOfRange)?,
        )
    }

    /// Marks a block used or free in the transaction being built.
    fn stage_bitmap(&mut self, block: u32, used: bool) -> Result<(), FsError> {
        let bit = u64::from(block);
        let byte = bit / 8;
        let holding = self.superblock.bitmap_start + byte / BLOCK as u64;
        if holding >= self.superblock.inode_start {
            return Err(FsError::OutOfRange);
        }
        let holding = u32::try_from(holding).map_err(|_| FsError::OutOfRange)?;
        let slot = self.stage(holding)?;
        let within = (byte % BLOCK as u64) as usize;
        let mask = 1u8 << (bit % 8);
        let staged = self.staged_mut(slot)?;
        let cell = staged.get_mut(within).ok_or(FsError::OutOfRange)?;
        if used {
            *cell |= mask;
        } else {
            *cell &= !mask;
        }
        Ok(())
    }

    /// The first free block, without taking it.
    fn free_block(&self) -> Result<u32, FsError> {
        crate::Free::of(self.bytes, &self.superblock)?
            .first()
            .ok_or(FsError::Full)
    }

    /// The first free inode, without taking it.
    fn free_inode(&self) -> Result<u32, FsError> {
        for index in 0..u32::try_from(self.superblock.inodes).unwrap_or(u32::MAX) {
            if Inode::read(self.bytes, &self.superblock, index)
                .is_ok_and(|inode| inode.kind == Kind::Free)
            {
                return Ok(index);
            }
        }
        Err(FsError::Full)
    }

    /// Creates `name` in `directory`, and returns the inode it got.
    ///
    /// # Errors
    ///
    /// [`FsError::WrongKind`] if `directory` is not one, [`FsError::BadName`]
    /// for a name this format cannot hold, [`FsError::Full`] if there is no
    /// free inode or block, and [`FsError::Interrupted`] if `watch` stopped it.
    pub fn create(
        &mut self,
        directory: u32,
        name: &[u8],
        kind: Kind,
        watch: &mut (impl Watch + ?Sized),
    ) -> Result<u32, FsError> {
        self.create_ordered(directory, name, kind, watch, &[])
    }

    /// [`Volume::create`], with the writes issued in a given order.
    ///
    /// # Errors
    ///
    /// As [`Volume::create`].
    pub fn create_ordered(
        &mut self,
        directory: u32,
        name: &[u8],
        kind: Kind,
        watch: &mut (impl Watch + ?Sized),
        order: &[usize],
    ) -> Result<u32, FsError> {
        if name.is_empty() || name.len() > crate::MAX_NAME {
            return Err(FsError::BadName);
        }
        if kind == Kind::Free {
            return Err(FsError::WrongKind);
        }
        let parent = self.inode(directory)?;
        if parent.kind != Kind::Directory {
            return Err(FsError::WrongKind);
        }
        // A name that is already there is refused before anything is staged. A
        // directory with two entries of one name is a directory where deleting
        // the file leaves the file.
        if self.lookup(directory, name).is_ok() {
            return Err(FsError::BadName);
        }

        let index = self.free_inode()?;
        let generation = self.inode(index).map(|old| old.generation).unwrap_or(0);
        let entries = (parent.size as usize) / ENTRY;
        let which = entries % (BLOCK / ENTRY);
        let block_index = entries / (BLOCK / ENTRY);
        if block_index >= parent.direct.len() {
            return Err(FsError::Full);
        }

        self.begin()?;

        // A new block for the directory, if this entry starts one.
        let mut parent = parent;
        if which == 0 {
            let block = self.free_block()?;
            self.stage_bitmap(block, true)?;
            let slot = self.stage(block)?;
            self.staged_mut(slot)?.fill(0);
            parent.direct[block_index] = block;
        }

        let block = parent.direct[block_index];
        if block == 0 || u64::from(block) >= self.superblock.blocks {
            return Err(FsError::OutOfRange);
        }
        let slot = self.stage(block)?;
        Entry::new(index, name)?.write(self.staged_mut(slot)?, which * ENTRY)?;

        parent.size += ENTRY as u64;
        self.stage_inode(directory, &parent)?;

        // The generation is bumped on *reuse*, so that a capability naming the
        // inode this slot used to hold resolves to nothing. Starting at one on
        // a slot never used before keeps zero out of circulation entirely: a
        // capability built from a zeroed page names nothing rather than inode
        // zero, generation zero.
        self.stage_inode(
            index,
            &Inode {
                kind,
                links: 1,
                generation: generation.wrapping_add(1).max(1),
                size: 0,
                direct: [0; 10],
                indirect: 0,
            },
        )?;

        self.commit(watch, order)?;
        Ok(index)
    }

    /// Finds `name` in `directory`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`], or [`FsError::WrongKind`] if `directory` is not
    /// one.
    pub fn lookup(&self, directory: u32, name: &[u8]) -> Result<(u32, Inode), FsError> {
        let mounted = crate::Filesystem::mounted(self.bytes, self.superblock);
        let inode = mounted.inode(directory)?;
        mounted.lookup(&inode, name)
    }

    /// Writes `data` at `offset` in the file `index` names.
    ///
    /// # Errors
    ///
    /// [`FsError::WrongKind`] on a directory, [`FsError::Full`] if a block is
    /// needed and there is none, and [`FsError::Interrupted`] if `watch`
    /// stopped it.
    pub fn write(
        &mut self,
        index: u32,
        offset: u64,
        data: &[u8],
        watch: &mut (impl Watch + ?Sized),
    ) -> Result<usize, FsError> {
        self.write_ordered(index, offset, data, watch, &[])
    }

    /// [`Volume::write`], with the writes issued in a given order.
    ///
    /// # Errors
    ///
    /// As [`Volume::write`].
    pub fn write_ordered(
        &mut self,
        index: u32,
        offset: u64,
        data: &[u8],
        watch: &mut (impl Watch + ?Sized),
        order: &[usize],
    ) -> Result<usize, FsError> {
        let mut inode = self.inode(index)?;
        if inode.kind != Kind::File {
            return Err(FsError::WrongKind);
        }
        // One block at a time, and the caller is told how much went. A write
        // spanning blocks would be several transactions, and several
        // transactions is several acknowledgements -- so saying so is more
        // honest than looping here and implying one.
        let within = (offset % BLOCK as u64) as usize;
        let room = BLOCK - within;
        let taking = data.len().min(room);
        let block_index =
            usize::try_from(offset / BLOCK as u64).map_err(|_| FsError::OutOfRange)?;
        if block_index >= inode.direct.len() {
            return Err(FsError::Full);
        }

        self.begin()?;

        let fresh = inode.direct[block_index] == 0;
        let block = if fresh {
            let block = self.free_block()?;
            self.stage_bitmap(block, true)?;
            inode.direct[block_index] = block;
            block
        } else {
            inode.direct[block_index]
        };
        if u64::from(block) >= self.superblock.blocks
            || u64::from(block) < self.superblock.data_start
        {
            return Err(FsError::OutOfRange);
        }

        // The data itself, straight to its home and *before* the commit that
        // will point an inode at it. RFC 0015 does not journal data; writing
        // it first is what stops a block an inode claims from ever having been
        // a block still holding somebody else's bytes. The cost is that an
        // overwrite is not atomic -- a crash mid-write tears the block -- and
        // that is the trade the RFC named: a crash may lose recent writes and
        // must not lose the filesystem.
        let mut contents = [0u8; BLOCK];
        if !fresh {
            contents.copy_from_slice(self.block(block)?);
        }
        contents
            .get_mut(within..within + taking)
            .ok_or(FsError::OutOfRange)?
            .copy_from_slice(&data[..taking]);
        self.put(block, &contents, watch)?;

        let end = offset + taking as u64;
        if end > inode.size {
            inode.size = end;
        }
        self.stage_inode(index, &inode)?;
        self.commit(watch, order)?;
        Ok(taking)
    }

    /// Removes `name` from `directory`, freeing what it named.
    ///
    /// The inode's generation is bumped, which is what makes a `Directory` or
    /// `File` capability naming it stop resolving. Until this existed, that
    /// check could only be tested against a capability the kernel manufactured.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`], [`FsError::WrongKind`] on a directory that is
    /// not empty, and [`FsError::Interrupted`] if `watch` stopped it.
    pub fn remove(
        &mut self,
        directory: u32,
        name: &[u8],
        watch: &mut (impl Watch + ?Sized),
    ) -> Result<(), FsError> {
        let parent = self.inode(directory)?;
        if parent.kind != Kind::Directory {
            return Err(FsError::WrongKind);
        }
        let (index, victim) = self.lookup(directory, name)?;
        if victim.kind == Kind::Directory && victim.size != 0 {
            return Err(FsError::WrongKind);
        }

        // Which entry, by walking the directory the way a reader does.
        let mut found = None;
        let entries = (parent.size as usize) / ENTRY;
        for at in 0..entries {
            let block = parent.direct[at / (BLOCK / ENTRY)];
            let offset = (at % (BLOCK / ENTRY)) * ENTRY;
            if let Ok(entry) = Entry::read(self.block(block)?, offset)
                && entry.name() == name
            {
                found = Some(at);
                break;
            }
        }
        let at = found.ok_or(FsError::NotFound)?;
        let last = entries - 1;

        self.begin()?;

        // The last entry is moved into the hole and the directory shrinks, so
        // a directory never has a gap in it. A tombstone would need every
        // reader to know about tombstones, and the reader is the part that
        // already works.
        let last_block = parent.direct[last / (BLOCK / ENTRY)];
        let last_offset = (last % (BLOCK / ENTRY)) * ENTRY;
        let moving = Entry::read(self.block(last_block)?, last_offset)?;

        let block = parent.direct[at / (BLOCK / ENTRY)];
        let offset = (at % (BLOCK / ENTRY)) * ENTRY;
        let slot = self.stage(block)?;
        moving.write(self.staged_mut(slot)?, offset)?;

        let mut parent = parent;
        parent.size -= ENTRY as u64;
        self.stage_inode(directory, &parent)?;

        // Freed, and its generation carried forward. The generation is the
        // only field of a dead inode that still matters: it is what a stale
        // capability is checked against, so zeroing it here would make every
        // capability to this inode start resolving again the moment the slot
        // was reused.
        self.stage_inode(
            index,
            &Inode {
                kind: Kind::Free,
                links: 0,
                generation: victim.generation,
                size: 0,
                direct: [0; 10],
                indirect: 0,
            },
        )?;
        for block in victim.direct.iter().take_while(|block| **block != 0) {
            self.stage_bitmap(*block, false)?;
        }

        self.commit(watch, &[])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::{BLOCK, Filesystem, Kind};

    /// Records every block written, in order, and stops nothing.
    #[derive(Default)]
    struct Trace(Vec<u32>);

    impl Watch for Trace {
        fn writing(&mut self, block: u32) -> bool {
            self.0.push(block);
            true
        }
    }

    fn image(blocks: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; blocks * BLOCK];
        crate::format(&mut bytes, 128).expect("a filesystem fits");
        bytes
    }

    /// Everything a reader can see, so that two images can be compared.
    ///
    /// Compared as a whole rather than field by field: a recovery that got the
    /// directory right and the size wrong is not a recovery, and a test that
    /// checked only what it thought of would say it was.
    fn visible(bytes: &[u8]) -> Vec<(Vec<u8>, u32, u64, Vec<u8>)> {
        let mounted = Filesystem::mount(bytes).expect("it mounts");
        let root = mounted.root().expect("with a root");
        let mut names = Vec::new();
        mounted.list(&root, |entry| names.push(entry.name().to_vec()));

        let mut seen = Vec::new();
        for name in names {
            let (index, inode) = mounted
                .lookup(&root, &name)
                .expect("an entry it just listed");
            let mut contents = vec![0u8; inode.size as usize];
            let read = mounted.read(&inode, 0, &mut contents);
            contents.truncate(read);
            seen.push((name, index, inode.generation as u64, contents));
        }
        seen.sort();
        seen
    }

    /// The image an operation starts from, and the one it should end at.
    fn before_and_after(
        run: &dyn Fn(&mut Volume<'_>, &mut dyn Watch),
    ) -> (Vec<u8>, Vec<u8>, Vec<u32>) {
        let before = image(64);

        let mut after = before.clone();
        {
            let (mut volume, replayed) =
                Volume::mount(&mut after, &mut Uninterrupted).expect("a fresh image mounts");
            assert_eq!(replayed, 0, "a fresh image has nothing to recover");
            run(&mut volume, &mut Uninterrupted);
        }

        // The same operation again, on a fresh image, only to record the
        // writes it makes. Recorded from a *separate* run so that the trace
        // cannot be an artefact of the image the assertions use -- and
        // asserted identical, which is also the check that an operation is
        // deterministic. One that was not would make every N below a
        // different experiment.
        let mut traced = before.clone();
        let mut trace = Trace::default();
        {
            let (mut volume, _) =
                Volume::mount(&mut traced, &mut Uninterrupted).expect("it mounts");
            run(&mut volume, &mut trace);
        }
        assert_eq!(
            traced, after,
            "the same operation twice gives the same image"
        );

        (before, after, trace.0)
    }

    /// One thing a filesystem can be asked to do, and the watch it does it under.
    type Operation = dyn Fn(&mut Volume<'_>, &mut dyn Watch) + 'static;

    #[test]
    fn a_file_created_and_written_reads_back() {
        let mut bytes = image(64);
        // The writable mount goes out of scope before the read-only one, which
        // is the one that has to agree with it.
        {
            let (mut volume, _) = Volume::mount(&mut bytes, &mut Uninterrupted).unwrap();
            let root = volume.superblock().root;
            let index = volume
                .create(root, b"written", Kind::File, &mut Uninterrupted)
                .expect("a file is created");
            let put = volume
                .write(
                    index,
                    0,
                    b"a filesystem this kernel can write to\n",
                    &mut Uninterrupted,
                )
                .expect("and written to");
            assert_eq!(put, 38);
        }

        let mounted = Filesystem::mount(&bytes).expect("and mounts read-only afterwards");
        let root = mounted.root().unwrap();
        let (_, inode) = mounted
            .lookup(&root, b"written")
            .expect("with the file in it");
        let mut contents = [0u8; 64];
        let read = mounted.read(&inode, 0, &mut contents);
        assert_eq!(
            &contents[..read],
            b"a filesystem this kernel can write to\n"
        );
    }

    #[test]
    fn a_transaction_has_exactly_one_shape() {
        // The ordering the whole journal rests on, asserted as a sequence
        // rather than as prose. A transaction of n blocks is: n writes into
        // the journal, the commit, n writes to the homes, the commit cleared.
        // Nothing outside the journal is touched before the commit, and the
        // commit is not written before the payload it checksums.
        //
        // Asserting the *shape* and not just "homes come after the commit" is
        // deliberate. A weaker assertion passed while the payload writes were
        // moved to after the commit -- the image came out identical, because
        // the payload is prepared in place and those writes put no new bytes
        // anywhere. The order they are *issued* in is what a real disk would
        // see, and this is the only thing that checks it.
        let (before, _, trace) =
            before_and_after(&|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                let root = volume.superblock().root;
                volume
                    .create(root, b"ordered", Kind::File, watch)
                    .expect("created");
            });

        let superblock = crate::Superblock::read(&before).unwrap();
        let commit = u32::try_from(superblock.journal_start).unwrap();
        let last = u32::try_from(superblock.journal_start + superblock.journal_blocks - 1).unwrap();

        assert_eq!(trace.len() % 2, 0, "a transaction is symmetric: {trace:?}");
        let staged = trace.len() / 2 - 1;
        assert!(staged > 0, "nothing was staged: {trace:?}");

        for (which, block) in trace[..staged].iter().enumerate() {
            assert!(
                *block > commit && *block <= last,
                "write {which} went to {block}, outside the journal, before the commit"
            );
        }
        assert_eq!(
            trace[staged], commit,
            "the commit does not follow its payload"
        );
        for (which, block) in trace[staged + 1..trace.len() - 1].iter().enumerate() {
            // Outside the journal, on either side of it: a home block may be a
            // bitmap block before the log or a data block after it, and an
            // assertion that said "below the commit" would be an assertion
            // about this image's layout rather than about the ordering.
            assert!(
                *block < commit || *block > last,
                "write {} went to {block}, still in the journal, after the commit",
                which + staged + 1
            );
        }
        assert_eq!(
            *trace.last().unwrap(),
            commit,
            "the log was not cleared once its blocks were home"
        );
    }

    #[test]
    fn an_interruption_at_every_write_leaves_a_filesystem() {
        // The claim, in full: after an interruption at *any* write, the
        // filesystem mounts, and what it holds is exactly the result of the
        // transactions that were committed -- no more and no less.
        //
        // "No more" is the half that is easy to get wrong and easy to skip. An
        // operation of two transactions interrupted between them must leave
        // the first and not the second; asserting only "before or after" would
        // pass a filesystem that had applied half of the second, and would
        // pass it while looking rigorous.
        for (what, stages) in operations() {
            // What the filesystem looks like after each prefix of the stages,
            // built by running those stages and no others. Independent of the
            // mechanism under test: no interruption, no recovery.
            let mut references = alloc::vec![image(64)];
            for upto in 1..=stages.len() {
                let mut bytes = image(64);
                {
                    let (mut volume, _) = Volume::mount(&mut bytes, &mut Uninterrupted).unwrap();
                    for stage in &stages[..upto] {
                        stage(&mut volume, &mut Uninterrupted);
                    }
                }
                references.push(bytes);
            }

            let whole = |volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                for stage in &stages {
                    stage(volume, watch);
                }
            };
            let (before, after, trace) = before_and_after(&whole);
            assert_eq!(visible(&after), visible(references.last().unwrap()));

            let superblock = crate::Superblock::read(&before).unwrap();
            let commit = u32::try_from(superblock.journal_start).unwrap();
            let commits: Vec<usize> = trace
                .iter()
                .enumerate()
                .filter(|(_, block)| **block == commit)
                .map(|(at, _)| at)
                .collect();
            // Two commits to a commit block per transaction: the one that
            // makes it certain and the one that clears it. Counting the pairs
            // is what says how many transactions there are, and asserting it
            // here means a change to the ordering cannot silently make this
            // test measure something else.
            assert_eq!(
                commits.len(),
                stages.len() * 2,
                "{what}: {} writes to the commit block for {} transactions",
                commits.len(),
                stages.len()
            );

            for stop in 0..=trace.len() {
                let mut bytes = before.clone();
                {
                    let mut watch = StopAfter::new(stop as u32);
                    if let Ok((mut volume, _)) = Volume::mount(&mut bytes, &mut Uninterrupted) {
                        whole(&mut volume, &mut watch);
                    }
                }

                // Whatever state that left, mounting it must work -- and
                // mounting it is what recovers it.
                let (_, replayed) =
                    Volume::mount(&mut bytes, &mut Uninterrupted).unwrap_or_else(|error| {
                        panic!("{what}: stopped after {stop} writes, it will not mount: {error:?}")
                    });

                let done = commits.chunks(2).filter(|pair| stop > pair[0]).count();
                assert_eq!(
                    visible(&bytes),
                    visible(&references[done]),
                    "{what}: stopped after {stop} of {} writes, {done} of {} transactions \
                     committed, replayed {replayed} blocks",
                    trace.len(),
                    stages.len()
                );
            }
        }
    }

    #[test]
    fn an_interruption_survives_the_writes_being_reordered() {
        // A device is entitled to reorder writes it has not been asked to
        // order. Within a phase, this issues them backwards -- which is the
        // permutation most likely to expose an assumption that the first write
        // of a phase is special.
        let reversed: Vec<usize> = (0..MAX_STAGED).rev().collect();
        let run = move |volume: &mut Volume<'_>, watch: &mut dyn Watch| {
            let root = volume.superblock().root;
            let staged = 3;
            let order: Vec<usize> = reversed[MAX_STAGED - staged..].to_vec();
            let _ = volume.create_ordered(root, b"backwards", Kind::File, watch, &order);
        };
        let (before, after, trace) = before_and_after(&run);
        let commit_at = commit_position(&before, &trace);
        assert_ne!(
            visible(&before),
            visible(&after),
            "the operation did something"
        );

        for stop in 0..=trace.len() {
            let mut bytes = before.clone();
            {
                let mut watch = StopAfter::new(stop as u32);
                if let Ok((mut volume, _)) = Volume::mount(&mut bytes, &mut Uninterrupted) {
                    run(&mut volume, &mut watch);
                }
            }
            let _ = Volume::mount(&mut bytes, &mut Uninterrupted)
                .unwrap_or_else(|error| panic!("reordered, stopped after {stop}: {error:?}"));
            let expected = if stop > commit_at { &after } else { &before };
            assert_eq!(
                visible(&bytes),
                visible(expected),
                "reordered, stopped after {stop} of {} writes",
                trace.len()
            );
        }
    }

    #[test]
    fn an_interruption_during_recovery_costs_only_another_recovery() {
        // Replay is idempotent, which is the property that lets the ordering
        // above be an ordering rather than a protocol. It is worth a test of
        // its own because it is invisible: a replay that were *not* idempotent
        // would pass every test above and fail only on the machine that
        // crashed twice.
        let (before, after, trace) =
            before_and_after(&|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                let root = volume.superblock().root;
                volume
                    .create(root, b"twice", Kind::File, watch)
                    .expect("created");
            });
        let commit_at = commit_position(&before, &trace);

        // An image stopped one write after the commit: committed, and its
        // homes not yet written.
        let mut crashed = before.clone();
        {
            let mut watch = StopAfter::new(commit_at as u32 + 1);
            if let Ok((mut volume, _)) = Volume::mount(&mut crashed, &mut Uninterrupted) {
                let root = volume.superblock().root;
                let _ = volume.create(root, b"twice", Kind::File, &mut watch);
            }
        }

        for stop in 0..8 {
            let mut bytes = crashed.clone();
            let mut watch = StopAfter::new(stop);
            let _ = Volume::mount(&mut bytes, &mut watch);
            let (_, replayed) = Volume::mount(&mut bytes, &mut Uninterrupted)
                .unwrap_or_else(|e| panic!("recovery stopped after {stop}: {e:?}"));
            assert_eq!(
                visible(&bytes),
                visible(&after),
                "a recovery stopped after {stop} writes and then finished, replaying {replayed}"
            );
        }
    }

    #[test]
    fn a_read_only_mount_refuses_an_image_that_needs_recovery() {
        let (before, _, trace) =
            before_and_after(&|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                let root = volume.superblock().root;
                volume
                    .create(root, b"pending", Kind::File, watch)
                    .expect("created");
            });
        let commit_at = commit_position(&before, &trace);

        let mut bytes = before.clone();
        {
            let mut watch = StopAfter::new(commit_at as u32 + 1);
            if let Ok((mut volume, _)) = Volume::mount(&mut bytes, &mut Uninterrupted) {
                let root = volume.superblock().root;
                let _ = volume.create(root, b"pending", Kind::File, &mut watch);
            }
        }

        // The read-only mount cannot replay it, so it must not mount it. The
        // state it would otherwise hand back is the one *before* an operation
        // that has already been acknowledged.
        assert_eq!(
            Filesystem::mount(&bytes).map(|_| ()).unwrap_err(),
            FsError::NeedsRecovery
        );

        // And after a writable mount has recovered it, the read-only mount
        // works again -- so this is a state and not a verdict on the image.
        let _ = Volume::mount(&mut bytes, &mut Uninterrupted).expect("recovers");
        assert!(Filesystem::mount(&bytes).is_ok());
    }

    #[test]
    fn a_log_that_does_not_add_up_is_not_replayed() {
        let (before, _, trace) =
            before_and_after(&|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                let root = volume.superblock().root;
                volume
                    .create(root, b"torn", Kind::File, watch)
                    .expect("created");
            });
        let commit_at = commit_position(&before, &trace);
        let superblock = crate::Superblock::read(&before).unwrap();

        let mut committed = before.clone();
        {
            let mut watch = StopAfter::new(commit_at as u32 + 1);
            if let Ok((mut volume, _)) = Volume::mount(&mut committed, &mut Uninterrupted) {
                let root = volume.superblock().root;
                let _ = volume.create(root, b"torn", Kind::File, &mut watch);
            }
        }
        assert!(journal::committed(&committed, &superblock).is_some());

        // A byte of the *payload* changed. The commit block is untouched and
        // still says what it said, which is the point: a checksum over the
        // header alone would replay this.
        let mut damaged = committed.clone();
        let payload = usize::try_from(superblock.journal_start + 1).unwrap() * BLOCK;
        damaged[payload + 9] ^= 0x40;
        assert!(journal::committed(&damaged, &superblock).is_none());
        let _ = Volume::mount(&mut damaged, &mut Uninterrupted).expect("it still mounts");
        assert_eq!(
            visible(&damaged),
            visible(&before),
            "a transaction that was not certain was applied anyway"
        );

        // A byte of the commit block changed, which is the torn-commit case.
        let mut torn = committed.clone();
        let head = usize::try_from(superblock.journal_start).unwrap() * BLOCK;
        torn[head + 9] ^= 0x40;
        let _ = Volume::mount(&mut torn, &mut Uninterrupted).expect("it still mounts");
        assert_eq!(visible(&torn), visible(&before));
    }

    #[test]
    fn a_log_naming_a_block_outside_the_image_refuses_to_mount() {
        let (before, _, trace) =
            before_and_after(&|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                let root = volume.superblock().root;
                volume
                    .create(root, b"forged", Kind::File, watch)
                    .expect("created");
            });
        let commit_at = commit_position(&before, &trace);
        let superblock = crate::Superblock::read(&before).unwrap();

        let mut bytes = before.clone();
        {
            let mut watch = StopAfter::new(commit_at as u32 + 1);
            if let Ok((mut volume, _)) = Volume::mount(&mut bytes, &mut Uninterrupted) {
                let root = volume.superblock().root;
                let _ = volume.create(root, b"forged", Kind::File, &mut watch);
            }
        }

        // The destination table says block zero -- the superblock. Every
        // number in a log came off a disk, so a replay that trusted them would
        // overwrite the one structure that describes where everything is, and
        // would do it *because* the log was valid.
        let head = usize::try_from(superblock.journal_start).unwrap() * BLOCK;
        bytes[head + 24..head + 28].copy_from_slice(&0u32.to_le_bytes());
        // and the checksum is repaired, so that only the range check can catch it.
        let repaired = {
            let mut hash = crate::checksum_of(0x811c_9dc5, &bytes[head..head + 20]);
            let count = crate::u32_at(&bytes[head..], 16).unwrap() as usize;
            hash = crate::checksum_of(hash, &bytes[head + 24..head + 24 + count * 4]);
            for index in 0..count {
                let at =
                    usize::try_from(superblock.journal_start + 1 + index as u64).unwrap() * BLOCK;
                hash = crate::checksum_of(hash, &bytes[at..at + BLOCK]);
            }
            if hash == 0 { 1 } else { hash }
        };
        bytes[head + 20..head + 24].copy_from_slice(&repaired.to_le_bytes());
        assert!(
            journal::committed(&bytes, &superblock).is_some(),
            "the log is valid"
        );

        assert_eq!(
            Volume::mount(&mut bytes, &mut Uninterrupted)
                .map(|_| ())
                .unwrap_err(),
            FsError::OutOfRange,
            "a log naming block zero was replayed over the superblock"
        );
    }

    #[test]
    fn removing_a_file_bumps_the_generation_of_what_reuses_it() {
        let mut bytes = image(64);
        let (mut volume, _) = Volume::mount(&mut bytes, &mut Uninterrupted).unwrap();
        let root = volume.superblock().root;

        let first = volume
            .create(root, b"gone", Kind::File, &mut Uninterrupted)
            .unwrap();
        volume
            .write(first, 0, b"contents", &mut Uninterrupted)
            .unwrap();
        let was = volume.inode(first).unwrap().generation;

        volume
            .remove(root, b"gone", &mut Uninterrupted)
            .expect("removed");
        assert!(volume.lookup(root, b"gone").is_err(), "and it is gone");
        assert_eq!(
            volume.inode(first).unwrap().generation,
            was,
            "a dead inode keeps its generation -- it is what a stale capability is checked against"
        );

        let again = volume
            .create(root, b"other", Kind::File, &mut Uninterrupted)
            .unwrap();
        assert_eq!(again, first, "the slot is reused");
        assert_ne!(
            volume.inode(again).unwrap().generation,
            was,
            "a capability naming the old file would resolve to the new one"
        );
    }

    #[test]
    fn a_full_filesystem_refuses_rather_than_half_writes() {
        let mut bytes = image(16);
        let mut names = Vec::new();
        {
            let (mut volume, _) = Volume::mount(&mut bytes, &mut Uninterrupted).unwrap();
            let root = volume.superblock().root;

            let mut made = 0;
            loop {
                let name = format!("file{made:03}");
                match volume.create(root, name.as_bytes(), Kind::File, &mut Uninterrupted) {
                    Ok(index) => {
                        // Recorded the moment it is acknowledged, before the write
                        // that may fail. Recording it afterwards made this test
                        // claim the last file had not been created, when it had --
                        // the test was wrong about which operations were
                        // acknowledged, which is the one thing it exists to know.
                        names.push(name);
                        made += 1;
                        // Each one gets a block, so the disk runs out.
                        if volume.write(index, 0, b"x", &mut Uninterrupted).is_err() {
                            break;
                        }
                    }
                    Err(FsError::Full) => break,
                    Err(other) => panic!("{other:?}"),
                }
                assert!(made < 4096, "it never filled up");
            }
            assert!(made > 0, "nothing was created at all");
        }

        // Full is a refusal, not a state to be repaired: everything that was
        // acknowledged is still there and the filesystem still mounts.
        let seen = visible(&bytes);
        assert_eq!(seen.len(), names.len());
        for name in &names {
            assert!(
                seen.iter().any(|(had, _, _, _)| had == name.as_bytes()),
                "{name} was acknowledged and is not there"
            );
        }
    }

    /// Where in `trace` the commit block is written.
    fn commit_position(bytes: &[u8], trace: &[u32]) -> usize {
        let superblock = crate::Superblock::read(bytes).unwrap();
        let commit = u32::try_from(superblock.journal_start).unwrap();
        trace
            .iter()
            .position(|block| *block == commit)
            .expect("every transaction writes a commit block")
    }

    /// The operations the harness runs, each on a fresh image.
    #[allow(clippy::type_complexity)]
    fn operations() -> Vec<(&'static str, Vec<Box<Operation>>)> {
        vec![
            (
                "create",
                alloc::vec![Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                    let root = volume.superblock().root;
                    let _ = volume.create(root, b"made", Kind::File, watch);
                }) as Box<Operation>],
            ),
            (
                "create, then write, then create again",
                alloc::vec![
                    Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"filled", Kind::File, watch);
                    }) as Box<Operation>,
                    Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                        let root = volume.superblock().root;
                        if let Ok((index, _)) = volume.lookup(root, b"filled") {
                            let _ = volume.write(index, 0, b"forty-two bytes of it", watch);
                        }
                    }),
                    Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"second", Kind::File, watch);
                    }),
                ],
            ),
            (
                "create and remove",
                alloc::vec![
                    Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"brief", Kind::File, watch);
                    }) as Box<Operation>,
                    Box::new(|volume: &mut Volume<'_>, watch: &mut dyn Watch| {
                        let root = volume.superblock().root;
                        let _ = volume.remove(root, b"brief", watch);
                    }),
                ],
            ),
        ]
    }
}
