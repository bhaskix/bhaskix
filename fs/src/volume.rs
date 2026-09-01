// SPDX-License-Identifier: Apache-2.0
//! Writing to a filesystem, through the journal and the cache.
//!
//! RFC 0015 steps 5 and 6, and they are one thing: a journal decides *when* a
//! change may reach the device, and a write-back cache is what makes "when" a
//! question at all. With write-through there is nothing to decide — every
//! change goes immediately, in whatever order it was made, which is the order
//! a journal exists to stop being the one that matters.
//!
//! So the transaction below is written in flushes rather than in assignments.
//! Changing a staged block is not a write; it is a promise. The four moments
//! that *are* writes are:
//!
//! 1. the payload reaching the device, before it can be committed to,
//! 2. the commit block — **the acknowledgement**,
//! 3. the changed blocks reaching their homes,
//! 4. and only then the log being cleared.
//!
//! Step four is the one the cache introduced and the one that is easy to
//! leave out: clearing the log while a changed page is still dirty throws away
//! the only record of a change that has not happened yet. The harness catches
//! it, because that is an interruption like any other.
//!
//! The interruption itself lives in the [`Store`] now — the device is the
//! thing that stops. A trace is therefore the sequence of writes the *device*
//! saw, which with a cache in the way is no longer the sequence the filesystem
//! asked for, and that difference is the whole of what a cache is.

use crate::cache::{Cache, Store};
use crate::{
    BLOCK, ENTRY, Entry, Filesystem, FsError, INODE, Inode, Kind, Pages, Superblock, journal,
    journal::MAX_STAGED,
};

/// A filesystem that can be written to.
///
/// Mounting one **recovers** it: there is no way to obtain a `Volume` whose
/// journal has not been replayed, because every way of getting one goes
/// through [`Volume::mount`]. A separate `recover()` a caller could forget to
/// call is the shape of this that has a bug in it.
pub struct Volume<'f, S: Store> {
    cache: Cache<'f, S>,
    superblock: Superblock,
    sequence: u64,
    staged: [u32; MAX_STAGED],
    count: usize,
}

impl<'f, S: Store> Volume<'f, S> {
    /// Mounts what `cache` holds, replaying any committed transaction first.
    ///
    /// Returns the volume and how many blocks the replay wrote — zero on a
    /// filesystem that was unmounted cleanly, which is the number the tests
    /// assert on to tell "recovered" from "there was nothing to recover".
    ///
    /// # Errors
    ///
    /// As [`Superblock::read_head`], and whatever the store returns —
    /// including [`FsError::Interrupted`] if it stopped during the replay.
    pub fn mount(mut cache: Cache<'f, S>) -> Result<(Self, u32), FsError> {
        let blocks = u64::from(cache.blocks());
        let head = cache.page(0)?;
        let superblock = Superblock::read_head(head, blocks)?;
        let mut volume = Self {
            cache,
            superblock,
            sequence: 0,
            staged: [0; MAX_STAGED],
            count: 0,
        };
        let replayed = volume.recover()?;
        Ok((volume, replayed))
    }

    /// What the superblock says.
    #[must_use]
    pub const fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Hits, misses and write-backs the cache has done.
    #[must_use]
    pub const fn counted(&self) -> (u64, u64, u64) {
        self.cache.counted()
    }

    /// The cache, to read through or to give back.
    pub const fn cache(&mut self) -> &mut Cache<'f, S> {
        &mut self.cache
    }

    /// A reader over the same cache.
    pub const fn reader(&mut self) -> Filesystem<'_, Cache<'f, S>> {
        Filesystem::using(&mut self.cache, self.superblock)
    }

    /// Replays a committed transaction, if there is one, and clears it.
    fn recover(&mut self) -> Result<u32, FsError> {
        let Some(commit) = journal::committed(&mut self.cache, &self.superblock)? else {
            // Nothing committed. The payload blocks may hold anything -- a
            // transaction that was being prepared when the machine stopped --
            // and it is all ignored, because what makes a transaction real is
            // the commit block and nothing else.
            return Ok(0);
        };

        self.sequence = commit.sequence;
        let start =
            u32::try_from(self.superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
        for index in 0..commit.count {
            let home = journal::home(&mut self.cache, &self.superblock, index)?;
            self.cache.copy(start + 1 + index, home)?;
        }
        // On the device before the log is cleared, for the same reason as in a
        // live transaction: a recovery that forgot the blocks it had just
        // replayed, and then destroyed the record of them, would turn a
        // survivable crash into a lost one on the *second* crash.
        self.cache.flush()?;

        self.clear_commit()?;
        Ok(commit.count)
    }

    /// Zeroes the commit block, so that nothing is pending.
    fn clear_commit(&mut self) -> Result<(), FsError> {
        let empty = [0u8; BLOCK];
        let block =
            u32::try_from(self.superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
        self.cache.put(block, &empty)?;
        self.cache.flush()?;
        Ok(())
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
    fn begin(&mut self) -> Result<(), FsError> {
        if journal::pending(&mut self.cache, &self.superblock)? {
            return Err(FsError::NeedsRecovery);
        }
        self.count = 0;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        Ok(())
    }

    /// The journal block a staged slot lives in.
    fn slot_block(&self, slot: usize) -> Result<u32, FsError> {
        u32::try_from(self.superblock.journal_start + 1 + slot as u64)
            .map_err(|_| FsError::OutOfRange)
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
        self.cache.copy(home, self.slot_block(slot)?)?;
        self.staged[slot] = home;
        self.count = slot + 1;
        Ok(slot)
    }

    /// The staged copy of a block, to be changed before it is committed.
    fn staged_mut(&mut self, slot: usize) -> Result<&mut [u8], FsError> {
        let block = self.slot_block(slot)?;
        self.cache.edit(block)
    }

    /// Puts the payload on the device, commits, applies, and clears.
    ///
    /// `order` permutes the writes *within* each phase — the payload among
    /// itself and the homes among themselves. It does not move a write across
    /// the commit, because that is the one ordering the journal depends on and
    /// a device that broke it would break every journal. What a device is
    /// entitled to reorder, this reorders.
    fn commit(&mut self, order: &[usize]) -> Result<(), FsError> {
        if self.count == 0 {
            return Ok(());
        }
        let straight: [usize; MAX_STAGED] = [0, 1, 2, 3, 4, 5, 6, 7];
        let order: &[usize] = if order.len() == self.count {
            order
        } else {
            &straight[..self.count]
        };

        // 1. The payload, onto the device. Until this has happened there is
        //    nothing to commit *to*: the commit block's checksum is over these
        //    blocks as the device holds them.
        self.cache.flush()?;

        // 2. The commit. Everything before this instant is provisional and
        //    everything after it is certain, and that is the only claim this
        //    filesystem makes about durability.
        let head = journal::build_commit(
            &mut self.cache,
            &self.superblock,
            self.sequence,
            &self.staged[..self.count],
        )?;
        let commit_block =
            u32::try_from(self.superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
        {
            let page = self.cache.edit(commit_block)?;
            page.fill(0);
            page.get_mut(..journal::HEAD)
                .ok_or(FsError::OutOfRange)?
                .copy_from_slice(&head);
        }
        self.cache.flush()?;

        // 3. Home. Interrupted here, the commit stands and the next mount
        //    finishes it.
        for slot in order {
            let home = self.staged[*slot];
            self.cache.copy(self.slot_block(*slot)?, home)?;
        }

        // 4. **On the device before the log is cleared.** This is the ordering
        //    the cache introduced. Clearing the log while a changed page is
        //    still dirty throws away the only record of a change that has not
        //    happened -- and it would do so at the moment everything looked
        //    finished.
        self.cache.flush()?;

        // 5. Done, so the log is empty again.
        self.clear_commit()?;
        self.count = 0;
        Ok(())
    }

    /// Gives the cache back, ending the mount.
    ///
    /// Safe at any point between public calls: every mutation on this type
    /// runs as one journal transaction and commits before returning, so
    /// there is never an open transaction to abandon here. What the cache
    /// then holds is a committed filesystem another mount can read —
    /// which is exactly how `bin/fsd` alternates between serving reads
    /// through [`crate::Filesystem`] and writing through this type
    /// (RFC 0030 step 3).
    pub fn into_cache(self) -> Cache<'f, S> {
        self.cache
    }

    /// Reads one inode.
    ///
    /// # Errors
    ///
    /// As [`Filesystem::inode`].
    pub fn inode(&mut self, index: u32) -> Result<Inode, FsError> {
        self.reader().inode(index)
    }

    /// Puts `inode` into the transaction being built.
    fn stage_inode(&mut self, index: u32, inode: &Inode) -> Result<(), FsError> {
        let (block, offset) = self.superblock.inode_at(index)?;
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

    /// The cache, for a test that needs to read a metadata block back.
    ///
    /// RFC 0065's removal test has to see which data block the indirect table
    /// names before the file is deleted, and there is no other way to ask.
    #[cfg(test)]
    pub(crate) fn cache_for_test(&mut self) -> &mut Cache<'f, S> {
        &mut self.cache
    }

    /// The first free block, without taking it.
    ///
    /// Reads the bitmap a block at a time, which is what a filesystem on a
    /// device has to do. The whole-image version could scan a slice; this
    /// cannot, and the difference is the reason the trait exists.
    #[cfg(test)]
    pub(crate) fn free_block_for_test(&mut self) -> Result<u32, FsError> {
        self.free_block()
    }

    fn free_block(&mut self) -> Result<u32, FsError> {
        self.free_block_excluding(u32::MAX)
    }

    /// [`Volume::free_block`], skipping one block already spoken for.
    ///
    /// **Because two allocations in one transaction collide** — RFC 0065.
    /// `stage_bitmap` edits a *journalled* copy of the bitmap and `free_block`
    /// reads the *cached* one, so a block claimed earlier in the same
    /// transaction still reads as free and is handed out twice. Nothing needed
    /// two until a write past the tenth block had to allocate an indirect table
    /// and a data block together, and the first version of that did exactly
    /// this: the table and the data were the same block, and the file's own
    /// bytes were read back as block numbers. Caught by the test written to
    /// prove the feature, which is what those are for.
    fn free_block_excluding(&mut self, taken: u32) -> Result<u32, FsError> {
        let first = self.superblock.data_start;
        for block in first..self.superblock.blocks {
            if block == u64::from(taken) {
                continue;
            }
            let byte = block / 8;
            let holding = self.superblock.bitmap_start + byte / BLOCK as u64;
            let holding = u32::try_from(holding).map_err(|_| FsError::OutOfRange)?;
            let page = self.cache.page(holding)?;
            let cell = *page
                .get((byte % BLOCK as u64) as usize)
                .ok_or(FsError::OutOfRange)?;
            if cell & (1 << (block % 8)) == 0 {
                return u32::try_from(block).map_err(|_| FsError::OutOfRange);
            }
        }
        Err(FsError::Full)
    }

    /// The first free inode, without taking it.
    fn free_inode(&mut self) -> Result<u32, FsError> {
        for index in 0..u32::try_from(self.superblock.inodes).unwrap_or(u32::MAX) {
            if self
                .inode(index)
                .is_ok_and(|inode| inode.kind == Kind::Free)
            {
                return Ok(index);
            }
        }
        Err(FsError::Full)
    }

    /// Finds `name` in `directory`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`], or [`FsError::WrongKind`] if `directory` is not
    /// one.
    pub fn lookup(&mut self, directory: u32, name: &[u8]) -> Result<(u32, Inode), FsError> {
        let mut reader = self.reader();
        let inode = reader.inode(directory)?;
        reader.lookup(&inode, name)
    }

    /// Creates `name` in `directory`, and returns the inode it got.
    ///
    /// # Errors
    ///
    /// [`FsError::WrongKind`] if `directory` is not one, [`FsError::BadName`]
    /// for a name this format cannot hold or one already there,
    /// [`FsError::Full`] if there is no free inode or block, and whatever the
    /// store returns.
    pub fn create(&mut self, directory: u32, name: &[u8], kind: Kind) -> Result<u32, FsError> {
        self.create_ordered(directory, name, kind, &[])
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
        let fresh = if which == 0 {
            Some(self.free_block()?)
        } else {
            None
        };

        self.begin()?;

        // A new block for the directory, if this entry starts one.
        let mut parent = parent;
        if let Some(block) = fresh {
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

        self.commit(order)?;
        Ok(index)
    }

    /// Writes `data` at `offset` in the file `index` names.
    ///
    /// # Errors
    ///
    /// [`FsError::WrongKind`] on a directory, [`FsError::Full`] if a block is
    /// needed and there is none, and whatever the store returns.
    pub fn write(&mut self, index: u32, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        self.write_ordered(index, offset, data, &[])
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
        // **The block the format already had** — RFC 0065. `Inode` has carried
        // an `indirect` since the format was written, `block_of` has always
        // followed it, and this function stopped at the tenth direct block --
        // so every file on this filesystem stopped at 40,960 bytes while the
        // reader was capable of far more. One table of 1,024 numbers takes that
        // to 4,239,360.
        const SLOTS: usize = BLOCK / 4;
        let direct_count = inode.direct.len();
        if block_index >= direct_count + SLOTS {
            return Err(FsError::Full);
        }
        let via_indirect = block_index >= direct_count;

        // The table itself, if this is the first block past the direct ones.
        // Allocated before `begin`, exactly as the data block is.
        let mut table_fresh = false;
        if via_indirect && inode.indirect == 0 {
            let table = self.free_block()?;
            if u64::from(table) >= self.superblock.blocks
                || u64::from(table) < self.superblock.data_start
            {
                return Err(FsError::OutOfRange);
            }
            inode.indirect = table;
            table_fresh = true;
        }

        // What is already there, out of the table or out of the inode. The
        // number read from the table is checked below with the direct ones,
        // and for the reason `block_of` gives: it came off a disk.
        let existing = if via_indirect {
            if table_fresh {
                0
            } else {
                let at = (block_index - direct_count) * 4;
                let table = self.cache.edit(inode.indirect)?;
                let mut number = [0u8; 4];
                number.copy_from_slice(table.get(at..at + 4).ok_or(FsError::OutOfRange)?);
                u32::from_le_bytes(number)
            }
        } else {
            inode.direct[block_index]
        };
        let fresh = existing == 0;
        let block = if fresh {
            // Not the table, if one was just claimed: see `free_block_excluding`.
            self.free_block_excluding(if table_fresh {
                inode.indirect
            } else {
                u32::MAX
            })?
        } else {
            existing
        };
        if u64::from(block) >= self.superblock.blocks
            || u64::from(block) < self.superblock.data_start
        {
            return Err(FsError::OutOfRange);
        }

        self.begin()?;
        if table_fresh {
            self.stage_bitmap(inode.indirect, true)?;
            self.cache.edit(inode.indirect)?.fill(0);
        }
        if fresh {
            self.stage_bitmap(block, true)?;
            if via_indirect {
                // **Into the table, and onto the device before the commit that
                // points an inode at the table.** The same ordering RFC 0015
                // states for data: a table an inode claims must never be a
                // block still holding somebody else's bytes. A crash between
                // the two leaks a block, which is the safe direction and the
                // one this filesystem already chooses.
                let at = (block_index - direct_count) * 4;
                let table = self.cache.edit(inode.indirect)?;
                table
                    .get_mut(at..at + 4)
                    .ok_or(FsError::OutOfRange)?
                    .copy_from_slice(&block.to_le_bytes());
            } else {
                inode.direct[block_index] = block;
            }
        }

        // The data itself, straight to its home and *onto the device* before
        // the commit that will point an inode at it. RFC 0015 does not journal
        // data; putting it there first is what stops a block an inode claims
        // from ever having been a block still holding somebody else's bytes.
        // The cost is that an overwrite is not atomic -- a crash mid-write
        // tears the block -- and that is the trade the RFC named: a crash may
        // lose recent writes and must not lose the filesystem.
        {
            let page = if fresh {
                let page = self.cache.edit(block)?;
                page.fill(0);
                page
            } else {
                self.cache.edit(block)?
            };
            page.get_mut(within..within + taking)
                .ok_or(FsError::OutOfRange)?
                .copy_from_slice(&data[..taking]);
        }
        self.cache.flush()?;

        let end = offset + taking as u64;
        if end > inode.size {
            inode.size = end;
        }
        self.stage_inode(index, &inode)?;
        self.commit(order)?;
        Ok(taking)
    }

    /// Removes `name` from `directory`, freeing what it named.
    ///
    /// The inode's generation is bumped when the slot is next used, which is
    /// what makes a `Directory` or `File` capability naming it stop resolving.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`], [`FsError::WrongKind`] on a directory that is
    /// not empty, and whatever the store returns.
    pub fn remove(&mut self, directory: u32, name: &[u8]) -> Result<(), FsError> {
        let parent = self.inode(directory)?;
        if parent.kind != Kind::Directory {
            return Err(FsError::WrongKind);
        }
        let (index, victim) = self.lookup(directory, name)?;
        if victim.kind == Kind::Directory && victim.size != 0 {
            return Err(FsError::WrongKind);
        }

        // Which entry, by walking the directory the way a reader does.
        let entries = (parent.size as usize) / ENTRY;
        let per = BLOCK / ENTRY;
        let mut found = None;
        for at in 0..entries {
            let block = parent.direct[at / per];
            let offset = (at % per) * ENTRY;
            let page = self.cache.page(block)?;
            if let Ok(entry) = Entry::read(page, offset)
                && entry.name() == name
            {
                found = Some(at);
                break;
            }
        }
        let at = found.ok_or(FsError::NotFound)?;
        let last = entries - 1;

        // The last entry is moved into the hole and the directory shrinks, so
        // a directory never has a gap in it. A tombstone would need every
        // reader to know about tombstones, and the reader is the part that
        // already works.
        let last_block = parent.direct[last / per];
        let last_offset = (last % per) * ENTRY;
        let moving = Entry::read(self.cache.page(last_block)?, last_offset)?;

        self.begin()?;

        let block = parent.direct[at / per];
        let offset = (at % per) * ENTRY;
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
        // **And whatever the indirect table named, then the table** — RFC 0065.
        // This loop freed the direct blocks alone, which was complete while
        // nothing could allocate a table; the moment a write can, a delete that
        // stopped here would leak up to 1,025 blocks per file.
        if victim.indirect != 0 {
            let mut numbers = [0u32; BLOCK / 4];
            {
                let table = self.cache.edit(victim.indirect)?;
                for (slot, number) in numbers.iter_mut().enumerate() {
                    let at = slot * 4;
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(table.get(at..at + 4).ok_or(FsError::OutOfRange)?);
                    *number = u32::from_le_bytes(bytes);
                }
            }
            for number in numbers.iter().take_while(|number| **number != 0) {
                self.stage_bitmap(*number, false)?;
            }
            self.stage_bitmap(victim.indirect, false)?;
        }

        self.commit(&[])
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
    use crate::cache::MIN_FRAMES;
    use crate::{BLOCK, Image, Kind};

    /// How many frames the tests give a cache, unless they are testing that.
    const FRAMES: usize = 16;

    /// A device that records what it was asked to write, and can stop.
    ///
    /// The interruption lives here now, and that is the point of the change:
    /// a write is interrupted at the device, not on the way to one. What this
    /// records is therefore what the *disk* saw — which, with a cache in front
    /// of it, is no longer what the filesystem asked for.
    struct Device<'a> {
        bytes: &'a mut [u8],
        trace: Vec<u32>,
        limit: Option<u32>,
    }

    impl<'a> Device<'a> {
        fn new(bytes: &'a mut [u8]) -> Self {
            Self {
                bytes,
                trace: Vec::new(),
                limit: None,
            }
        }

        fn stopping(bytes: &'a mut [u8], after: u32) -> Self {
            Self {
                bytes,
                trace: Vec::new(),
                limit: Some(after),
            }
        }
    }

    impl Store for Device<'_> {
        fn blocks(&self) -> u32 {
            u32::try_from(self.bytes.len() / BLOCK).unwrap_or(u32::MAX)
        }

        fn read(&mut self, block: u32, into: &mut [u8]) -> Result<(), FsError> {
            let at = (block as usize)
                .checked_mul(BLOCK)
                .ok_or(FsError::OutOfRange)?;
            let from = self.bytes.get(at..at + BLOCK).ok_or(FsError::OutOfRange)?;
            into.get_mut(..BLOCK)
                .ok_or(FsError::OutOfRange)?
                .copy_from_slice(from);
            Ok(())
        }

        fn write(&mut self, block: u32, from: &[u8]) -> Result<(), FsError> {
            if self.limit == Some(u32::try_from(self.trace.len()).unwrap_or(u32::MAX)) {
                // The machine stopped. Nothing is recorded and nothing lands,
                // which is what "it did not happen" means.
                return Err(FsError::Interrupted);
            }
            let at = (block as usize)
                .checked_mul(BLOCK)
                .ok_or(FsError::OutOfRange)?;
            let into = self
                .bytes
                .get_mut(at..at + BLOCK)
                .ok_or(FsError::OutOfRange)?;
            into.copy_from_slice(from.get(..BLOCK).ok_or(FsError::OutOfRange)?);
            self.trace.push(block);
            Ok(())
        }
    }

    fn image(blocks: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; blocks * BLOCK];
        crate::format(&mut bytes, 128).expect("a filesystem fits");
        bytes
    }

    /// Runs `f` against `bytes` as a device, and returns what the device saw.
    fn run(
        bytes: &mut [u8],
        frames: usize,
        stop: Option<u32>,
        f: impl FnOnce(&mut Volume<'_, Device<'_>>),
    ) -> Vec<u32> {
        let mut pages = vec![0u8; frames * BLOCK];
        let device = match stop {
            Some(after) => Device::stopping(bytes, after),
            None => Device::new(bytes),
        };
        let cache = Cache::new(&mut pages, device).expect("enough frames");
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            return Vec::new();
        };
        f(&mut volume);
        volume.cache().store().trace.clone()
    }

    /// Mounts for writing, which is what recovers, and says how much it replayed.
    fn recover(bytes: &mut [u8]) -> Result<u32, FsError> {
        let mut pages = vec![0u8; FRAMES * BLOCK];
        let cache = Cache::new(&mut pages, Device::new(bytes)).unwrap();
        Volume::mount(cache).map(|(_, replayed)| replayed)
    }

    /// Everything a reader can see, so that two images can be compared.
    ///
    /// Read straight off the device through an [`Image`], with no cache: what
    /// a cache remembers is exactly what these tests must not be allowed to
    /// count as durable.
    fn visible(bytes: &[u8]) -> Vec<(Vec<u8>, u32, u64, Vec<u8>)> {
        let mut pages = Image::new(bytes);
        let mut mounted = Filesystem::mount(&mut pages).expect("it mounts");
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
            seen.push((name, index, u64::from(inode.generation), contents));
        }
        seen.sort();
        seen
    }

    /// One thing a filesystem can be asked to do.
    type Operation = dyn Fn(&mut Volume<'_, Device<'_>>) + 'static;

    /// The image an operation starts from, the one it ends at, and the trace.
    fn before_and_after(
        what: &dyn Fn(&mut Volume<'_, Device<'_>>),
    ) -> (Vec<u8>, Vec<u8>, Vec<u32>) {
        let before = image(64);

        let mut after = before.clone();
        run(&mut after, FRAMES, None, what);

        // The same operation again, on a fresh image, only to record what the
        // device saw. Recorded from a *separate* run so that the trace cannot
        // be an artefact of the image the assertions use -- and asserted
        // identical, which is also the check that an operation is
        // deterministic. One that was not would make every N below a different
        // experiment.
        let mut traced = before.clone();
        let trace = run(&mut traced, FRAMES, None, what);
        assert_eq!(
            traced, after,
            "the same operation twice gives the same image"
        );

        (before, after, trace)
    }

    #[test]
    fn a_file_created_and_written_reads_back() {
        let mut bytes = image(64);
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let index = volume
                .create(root, b"written", Kind::File)
                .expect("a file is created");
            let put = volume
                .write(index, 0, b"a filesystem this kernel can write to\n")
                .expect("and written to");
            assert_eq!(put, 38);
        });

        // Off the device, through a reader that has never seen the cache.
        let mut pages = Image::new(&bytes);
        let mut mounted = Filesystem::mount(&mut pages).expect("and mounts afterwards");
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
    fn a_write_past_the_tenth_block_lands_in_the_indirect_table() {
        // **The limit this filesystem had and did not record** — RFC 0065.
        // `Inode` has carried an `indirect` since the format was written and
        // `block_of` has always followed it; `write_ordered` stopped at the
        // tenth direct block, so every file stopped at 40,960 bytes. This test
        // fails against that code, which is the whole reason it exists.
        let mut bytes = image(256);
        let eleventh = 10 * BLOCK as u64;
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let index = volume
                .create(root, b"long", Kind::File)
                .expect("a file is created");
            // The tenth block, which always worked.
            assert_eq!(
                volume
                    .write(index, 9 * BLOCK as u64, b"ten")
                    .expect("direct"),
                3
            );
            // And the eleventh, which did not.
            assert_eq!(
                volume
                    .write(index, eleventh, b"eleven")
                    .expect("past the direct blocks"),
                6
            );
            assert_ne!(
                volume.inode(index).expect("the inode").indirect,
                0,
                "a table was allocated"
            );
        });

        // Read back through a reader that has never seen the cache, because
        // the point is that this survives to the device and comes back.
        let mut pages = Image::new(&bytes);
        let mut mounted = Filesystem::mount(&mut pages).expect("mounts afterwards");
        let root = mounted.root().unwrap();
        let (_, inode) = mounted.lookup(&root, b"long").expect("with the file in it");
        let mut contents = [0u8; 8];
        let read = mounted.read(&inode, eleventh, &mut contents);
        assert_eq!(
            (inode.indirect != 0, inode.size),
            (true, eleventh + 6),
            "the table and the size reach the device"
        );
        assert_eq!(&contents[..read], b"eleven");
        assert_eq!(inode.size, eleventh + 6);
    }

    #[test]
    fn the_indirect_table_is_allocated_once_and_reused() {
        // A second write past the tenth block must land in the table that is
        // already there. Allocating a second one would strand the first and
        // lose every block it named.
        let mut bytes = image(256);
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let index = volume.create(root, b"long", Kind::File).expect("created");
            volume
                .write(index, 10 * BLOCK as u64, b"a")
                .expect("eleventh");
            let first = volume.inode(index).expect("inode").indirect;
            volume
                .write(index, 12 * BLOCK as u64, b"b")
                .expect("thirteenth");
            assert_eq!(
                volume.inode(index).expect("inode").indirect,
                first,
                "one table, not two"
            );
        });
    }

    #[test]
    fn a_file_past_the_indirect_table_is_still_refused() {
        // The limit moved; it did not go away. Ten direct plus 1,024 in the
        // table is 4,239,360 bytes, and the block after that is `Full` --
        // refused rather than silently dropped, which is the failure that made
        // this defect invisible in the first place.
        let mut bytes = image(64);
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let index = volume.create(root, b"long", Kind::File).expect("created");
            let past = (10 + BLOCK / 4) as u64 * BLOCK as u64;
            assert_eq!(
                volume.write(index, past, b"x"),
                Err(FsError::Full),
                "past the table is refused, not truncated"
            );
        });
    }

    #[test]
    fn removing_a_long_file_frees_the_table_and_what_it_named() {
        // `remove` freed the direct blocks alone, which was complete while
        // nothing could allocate a table. The moment a write can, a delete
        // that stopped there leaks up to 1,025 blocks per file -- proven here
        // by counting what the allocator will hand out afterwards.
        let mut bytes = image(256);
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let index = volume.create(root, b"long", Kind::File).expect("created");
            volume
                .write(index, 10 * BLOCK as u64, b"a")
                .expect("eleventh");
            let table = volume.inode(index).expect("inode").indirect;
            let data = {
                let at = 0;
                let page = volume.cache_for_test().edit(table).expect("the table");
                let mut number = [0u8; 4];
                number.copy_from_slice(&page[at..at + 4]);
                u32::from_le_bytes(number)
            };
            assert_ne!(data, 0, "the eleventh block is named in the table");

            volume.remove(root, b"long").expect("removed");

            // Both must be back in the allocator's hands. Asking for two and
            // getting these two is the strongest available check that neither
            // was leaked -- and the second ask must exclude the first, because
            // nothing has staged the bitmap in between and `free_block` would
            // otherwise hand out the same number twice. That is the very
            // collision this RFC had to fix in the write path, met again here
            // by the test written to check the fix.
            let first = volume.free_block_for_test().expect("a free block");
            let second = volume
                .free_block_excluding(first)
                .expect("and a second one");
            let handed = [first, second];
            assert!(
                handed.contains(&table) && handed.contains(&data),
                "the table and its block came back: got {handed:?}, wanted {table} and {data}"
            );
        });
    }

    #[test]
    fn a_transaction_has_exactly_one_shape() {
        // The ordering the whole journal rests on, asserted as a sequence
        // rather than as prose -- and now as the sequence the *device* saw. A
        // transaction of n blocks is: n writes into the journal, the commit,
        // n writes to the homes, the commit cleared. Nothing outside the
        // journal is touched before the commit, and the commit is not written
        // before the payload it checksums.
        //
        // Asserting the shape and not just "homes come after the commit" is
        // deliberate. A weaker assertion passed while the payload writes were
        // moved to after the commit.
        let (before, _, trace) = before_and_after(&|volume: &mut Volume<'_, Device<'_>>| {
            let root = volume.superblock().root;
            volume
                .create(root, b"ordered", Kind::File)
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
        // The claim, in full: after an interruption at *any* device write, the
        // filesystem mounts, and what it holds is exactly the result of the
        // transactions that were committed -- no more and no less.
        //
        // "No more" is the half that is easy to get wrong and easy to skip. An
        // operation of several transactions interrupted between them must
        // leave the first and not the second; asserting only "before or after"
        // would pass a filesystem that had applied half of the second, and
        // would pass it while looking rigorous.
        for (what, stages) in operations() {
            // What the filesystem looks like after each prefix of the stages,
            // built by running those stages and no others. Independent of the
            // mechanism under test: no interruption, no recovery.
            let mut references = vec![image(64)];
            for upto in 1..=stages.len() {
                let mut bytes = image(64);
                run(&mut bytes, FRAMES, None, |volume| {
                    for stage in &stages[..upto] {
                        stage(volume);
                    }
                });
                references.push(bytes);
            }

            let whole = |volume: &mut Volume<'_, Device<'_>>| {
                for stage in &stages {
                    stage(volume);
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
            // Two writes to the commit block per transaction: the one that
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
                run(&mut bytes, FRAMES, Some(stop as u32), whole);

                // Whatever state that left, mounting it must work -- and
                // mounting it is what recovers it.
                let replayed = recover(&mut bytes).unwrap_or_else(|error| {
                    panic!("{what}: stopped after {stop} writes, it will not mount: {error:?}")
                });

                let done = commits.chunks(2).filter(|pair| stop > pair[0]).count();
                assert_eq!(
                    visible(&bytes),
                    visible(&references[done]),
                    "{what}: stopped after {stop} of {} device writes, {done} of {} transactions \
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
        // order. Within a phase, this issues them backwards -- the permutation
        // most likely to expose an assumption that the first write of a phase
        // is special.
        let staged = 3;
        let order: Vec<usize> = (0..staged).rev().collect();
        let backwards = move |volume: &mut Volume<'_, Device<'_>>| {
            let root = volume.superblock().root;
            let _ = volume.create_ordered(root, b"backwards", Kind::File, &order);
        };
        let (before, after, trace) = before_and_after(&backwards);
        assert_ne!(
            visible(&before),
            visible(&after),
            "the operation did something"
        );

        let superblock = crate::Superblock::read(&before).unwrap();
        let commit = u32::try_from(superblock.journal_start).unwrap();
        let commit_at = trace.iter().position(|block| *block == commit).unwrap();

        for stop in 0..=trace.len() {
            let mut bytes = before.clone();
            run(&mut bytes, FRAMES, Some(stop as u32), &backwards);
            recover(&mut bytes)
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
        let (before, after, _) = before_and_after(&|volume: &mut Volume<'_, Device<'_>>| {
            let root = volume.superblock().root;
            volume.create(root, b"twice", Kind::File).expect("created");
        });
        let crashed = interrupted_after_commit(&before, b"twice");

        for stop in 0..8 {
            let mut bytes = crashed.clone();
            {
                let mut pages = vec![0u8; FRAMES * BLOCK];
                let cache = Cache::new(&mut pages, Device::stopping(&mut bytes, stop)).unwrap();
                let _ = Volume::mount(cache);
            }
            let replayed = recover(&mut bytes)
                .unwrap_or_else(|e| panic!("recovery stopped after {stop} writes: {e:?}"));
            assert_eq!(
                visible(&bytes),
                visible(&after),
                "a recovery stopped after {stop} writes and then finished, replaying {replayed}"
            );
        }
    }

    #[test]
    fn a_read_only_mount_refuses_an_image_that_needs_recovery() {
        let before = image(64);
        let mut bytes = interrupted_after_commit(&before, b"pending");

        // The read-only mount cannot replay it, so it must not mount it. The
        // state it would otherwise hand back is the one *before* an operation
        // that has already been acknowledged.
        let mut pages = Image::new(&bytes);
        assert_eq!(
            Filesystem::mount(&mut pages).map(|_| ()).unwrap_err(),
            FsError::NeedsRecovery
        );

        // And after a writable mount has recovered it, the read-only mount
        // works again -- so this is a state and not a verdict on the image.
        recover(&mut bytes).expect("recovers");
        let mut pages = Image::new(&bytes);
        assert!(Filesystem::mount(&mut pages).is_ok());
    }

    #[test]
    fn a_log_that_does_not_add_up_is_not_replayed() {
        let before = image(64);
        let committed = interrupted_after_commit(&before, b"torn");
        let superblock = crate::Superblock::read(&before).unwrap();

        // A byte of the *payload* changed. The commit block is untouched and
        // still says what it said, which is the point: a checksum over the
        // header alone would replay this.
        let mut damaged = committed.clone();
        let payload = usize::try_from(superblock.journal_start + 1).unwrap() * BLOCK;
        damaged[payload + 9] ^= 0x40;
        recover(&mut damaged).expect("it still mounts");
        assert_eq!(
            visible(&damaged),
            visible(&before),
            "a transaction that was not certain was applied anyway"
        );

        // A byte of the commit block changed, which is the torn-commit case.
        let mut torn = committed;
        let head = usize::try_from(superblock.journal_start).unwrap() * BLOCK;
        torn[head + 9] ^= 0x40;
        recover(&mut torn).expect("it still mounts");
        assert_eq!(visible(&torn), visible(&before));
    }

    #[test]
    fn a_log_naming_a_block_outside_the_image_refuses_to_mount() {
        let before = image(64);
        let mut bytes = interrupted_after_commit(&before, b"forged");
        let superblock = crate::Superblock::read(&before).unwrap();

        // The destination table says block zero -- the superblock. Every
        // number in a log came off a disk, so a replay that trusted them would
        // overwrite the one structure that describes where everything is, and
        // would do it *because* the log was valid.
        let head = usize::try_from(superblock.journal_start).unwrap() * BLOCK;
        bytes[head + 24..head + 28].copy_from_slice(&0u32.to_le_bytes());
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

        assert_eq!(
            recover(&mut bytes).unwrap_err(),
            FsError::OutOfRange,
            "a log naming block zero was replayed over the superblock"
        );
    }

    #[test]
    fn removing_a_file_bumps_the_generation_of_what_reuses_it() {
        let mut bytes = image(64);
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let first = volume.create(root, b"gone", Kind::File).unwrap();
            volume.write(first, 0, b"contents").unwrap();
            let was = volume.inode(first).unwrap().generation;

            volume.remove(root, b"gone").expect("removed");
            assert!(volume.lookup(root, b"gone").is_err(), "and it is gone");
            assert_eq!(
                volume.inode(first).unwrap().generation,
                was,
                "a dead inode keeps its generation -- a stale capability is checked against it"
            );

            let again = volume.create(root, b"other", Kind::File).unwrap();
            assert_eq!(again, first, "the slot is reused");
            assert_ne!(
                volume.inode(again).unwrap().generation,
                was,
                "a capability naming the old file would resolve to the new one"
            );
        });
    }

    #[test]
    fn a_full_filesystem_refuses_rather_than_half_writes() {
        let mut bytes = image(24);
        let mut names = Vec::new();
        run(&mut bytes, FRAMES, None, |volume| {
            let root = volume.superblock().root;
            let mut made = 0;
            loop {
                let name = format!("file{made:03}");
                match volume.create(root, name.as_bytes(), Kind::File) {
                    Ok(index) => {
                        // Recorded the moment it is acknowledged, before the
                        // write that may fail. Recording it afterwards made
                        // this test claim the last file had not been created
                        // when it had -- the test was wrong about which
                        // operations were acknowledged, which is the one thing
                        // it exists to know.
                        names.push(name);
                        made += 1;
                        if volume.write(index, 0, b"x").is_err() {
                            break;
                        }
                    }
                    Err(FsError::Full) => break,
                    Err(other) => panic!("{other:?}"),
                }
                assert!(made < 4096, "it never filled up");
            }
            assert!(made > 0, "nothing was created at all");
        });

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

    #[test]
    fn the_two_ways_of_reading_the_bitmap_agree() {
        // There are two, and there had to be. `Bitmap` holds the whole region
        // at once, which is what `format` and the image builder need and what
        // a device cannot give; `Volume::free_block` walks it a page at a
        // time, which is what a device forces. Two answers to "which block is
        // free" is one block handed to two files, so they are pinned to each
        // other here rather than trusted to stay in step.
        let mut bytes = image(64);
        let superblock = crate::Superblock::read(&bytes).unwrap();

        for _ in 0..4 {
            let whole = {
                let mut bitmap = crate::Bitmap::of(&mut bytes, &superblock).unwrap();
                let first = bitmap.first_free().expect("a free block");
                // Taken, so the next round asks a different question.
                bitmap.allocate().expect("and it can be taken");
                first
            };

            let mut pages = vec![0u8; FRAMES * BLOCK];
            let cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
            let (mut volume, _) = Volume::mount(cache).unwrap();
            assert_eq!(
                volume.free_block_for_test().unwrap(),
                whole + 1,
                "the page-by-page scan and the whole-region one disagree"
            );
        }
    }

    #[test]
    fn a_cached_block_is_not_read_from_the_device_twice() {
        // What a cache is for, stated as a number. Without it every structure
        // this filesystem touches is a device round trip, and reading one
        // directory entry means reading the superblock, a bitmap block, an
        // inode block and a data block -- every time.
        let mut bytes = image(64);
        let mut pages = vec![0u8; FRAMES * BLOCK];
        let mut cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();

        let first = cache.page(1).expect("a block").to_vec();
        let (hits, misses, _) = cache.counted();
        assert_eq!((hits, misses), (0, 1), "the first read went to the device");

        let again = cache.page(1).expect("the same block");
        assert_eq!(again, &first[..], "and gave the same bytes");
        let (hits, misses, _) = cache.counted();
        assert_eq!((hits, misses), (1, 1), "the second did not");

        // And what it says is what the device says, which a cache that
        // answered from nowhere would also appear to do.
        assert_eq!(&first[..], &cache.store().bytes[BLOCK..2 * BLOCK]);
    }

    #[test]
    fn an_evicted_page_is_written_rather_than_lost() {
        // A dirty page evicted to make room is a device write that happens
        // because somebody read something *else*. If it were dropped instead,
        // a change that had been made would silently not have been -- and
        // nothing above would notice, because every test there flushes.
        let mut bytes = image(64);
        let marker = [0xa5u8; BLOCK];
        {
            let mut pages = vec![0u8; MIN_FRAMES * BLOCK];
            let mut cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
            cache.put(40, &marker).expect("a dirty page");
            // Two more blocks, on a two-frame cache: the dirty one must go.
            let _ = cache.page(41).expect("a read");
            let _ = cache.page(42).expect("another");
            assert!(!cache.dirty(), "it is still holding the change");
            let (_, _, written) = cache.counted();
            assert_eq!(written, 1, "it did not write the page it evicted");
        }
        assert_eq!(&bytes[40 * BLOCK..41 * BLOCK], &marker[..]);
    }

    #[test]
    fn a_lent_frame_is_never_the_one_reused() {
        // RFC 0016 step 5, and the only claim here whose failure is silent: a
        // frame lent out and then given to another block is a holder reading
        // somebody else's data, with nothing to see and nothing to log.
        //
        // So this is not "eviction respects a pin once". Every read below
        // forces a choice, and the pinned frame is checked after **every one**
        // -- both that it still names its block and that its bytes are the
        // bytes that were lent.
        let mut bytes = image(64);
        let marker = [0x5au8; BLOCK];
        {
            let mut pages = vec![0u8; 4 * BLOCK];
            let mut cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
            cache.put(40, &marker).expect("a block to lend");
            cache.flush().expect("on the device");

            let lent = cache.pin(40).expect("held");
            assert!(cache.pinned(lent));

            // Far more reads than frames, so every unpinned frame is chosen
            // several times over.
            //
            // The lent frame is checked with `block_in`, which does **not**
            // want it. Checking with `page` was the first version, and it kept
            // block 40 permanently the most recently used frame -- so nothing
            // would ever have evicted it, pin or no pin, and the test passed
            // with the pin deleted.
            for round in 0..3 {
                for block in 41..=52u32 {
                    let seen = cache.page(block).expect("a read").to_vec();
                    assert_eq!(seen.len(), BLOCK);

                    assert_eq!(
                        cache.block_in(lent),
                        Some(40),
                        "round {round}, after reading {block}: the lent frame was reused"
                    );
                    assert!(
                        cache.pinned(lent),
                        "round {round}, after reading {block}: the pin was lost"
                    );
                }
            }

            // And its bytes are the bytes that were lent -- read last, once
            // the choosing is over, so that reading them cannot be what kept
            // them.
            assert_eq!(cache.page(40).expect("the lent block"), &marker[..]);
            assert_eq!(cache.pin(40).expect("still held"), lent);
        }
    }

    #[test]
    fn a_cache_with_every_frame_lent_refuses_rather_than_reusing_one() {
        // The other half. A rule that is only obeyed while there is something
        // else to take is not a rule, so this takes everything else away.
        let mut bytes = image(64);
        let mut pages = vec![0u8; MIN_FRAMES * BLOCK];
        let mut cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
        for block in 40..40 + MIN_FRAMES as u32 {
            cache.pin(block).expect("held");
        }
        assert_eq!(
            cache.page(50).map(|_| ()).unwrap_err(),
            FsError::Full,
            "a cache with nothing it may reuse took something it had lent"
        );

        // Letting one go makes room again, which is what says the refusal was
        // about the pins and not about the cache being broken.
        cache.unpin(0);
        assert!(cache.page(50).is_ok());
    }

    #[test]
    fn forgetting_keeps_what_is_lent() {
        // `forget` is about what the cache *remembers*. What somebody else is
        // holding is not the cache's to forget, and a frame dropped while lent
        // is the same disclosure by a quieter route.
        let mut bytes = image(64);
        let marker = [0x77u8; BLOCK];
        let mut pages = vec![0u8; 4 * BLOCK];
        let mut cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
        cache.put(41, &marker).unwrap();
        cache.flush().unwrap();
        let lent = cache.pin(41).unwrap();
        let _ = cache.page(42).unwrap();

        cache.forget();
        assert!(
            cache.pinned(lent),
            "forgetting dropped a frame that was lent"
        );
        assert_eq!(cache.page(41).unwrap(), &marker[..]);
    }

    #[test]
    fn the_smallest_cache_a_filesystem_can_have_still_works() {
        // Two frames, which is what copying a block to another block needs and
        // nothing more. Everything above runs with sixteen; a cache that only
        // worked when it was big enough not to evict would be hiding every
        // eviction bug behind its own size.
        let mut bytes = image(64);
        let mut pages = vec![0u8; MIN_FRAMES * BLOCK];
        let cache = Cache::new(&mut pages, Device::new(&mut bytes)).unwrap();
        let (mut volume, _) = Volume::mount(cache).expect("it mounts");
        let root = volume.superblock().root;
        volume
            .create(root, b"cramped", Kind::File)
            .expect("created");
        let index = volume.lookup(root, b"cramped").unwrap().0;
        volume.write(index, 0, b"on two frames").expect("written");
        drop(volume);

        assert_eq!(
            visible(&bytes)
                .into_iter()
                .map(|(name, _, _, contents)| (name, contents))
                .collect::<Vec<_>>(),
            vec![(b"cramped".to_vec(), b"on two frames".to_vec())]
        );

        // And one frame is refused rather than made to work: a copy needs two
        // resident at once, and a cache that pretended otherwise would read
        // its own source back from the device on every block it moved.
        let mut one = vec![0u8; BLOCK];
        let mut more = image(64);
        assert_eq!(
            Cache::new(&mut one, Device::new(&mut more))
                .map(|_| ())
                .unwrap_err(),
            FsError::OutOfRange
        );
    }

    /// An image with a transaction committed and nothing applied.
    fn interrupted_after_commit(before: &[u8], name: &[u8]) -> Vec<u8> {
        let mut bytes = before.to_vec();
        let make = |volume: &mut Volume<'_, Device<'_>>| {
            let root = volume.superblock().root;
            let _ = volume.create(root, name, Kind::File);
        };
        let trace = {
            let mut probe = before.to_vec();
            run(&mut probe, FRAMES, None, make)
        };
        let superblock = crate::Superblock::read(before).unwrap();
        let commit = u32::try_from(superblock.journal_start).unwrap();
        let at = trace.iter().position(|block| *block == commit).unwrap();
        run(&mut bytes, FRAMES, Some(at as u32 + 1), make);
        bytes
    }

    /// The operations the harness runs, each on a fresh image.
    fn operations() -> Vec<(&'static str, Vec<Box<Operation>>)> {
        vec![
            (
                "create",
                vec![Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                    let root = volume.superblock().root;
                    let _ = volume.create(root, b"made", Kind::File);
                }) as Box<Operation>],
            ),
            (
                "create, then write, then create again",
                vec![
                    Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"filled", Kind::File);
                    }) as Box<Operation>,
                    Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                        let root = volume.superblock().root;
                        if let Ok((index, _)) = volume.lookup(root, b"filled") {
                            let _ = volume.write(index, 0, b"forty-two bytes of it");
                        }
                    }),
                    Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"second", Kind::File);
                    }),
                ],
            ),
            (
                "create and remove",
                vec![
                    Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                        let root = volume.superblock().root;
                        let _ = volume.create(root, b"brief", Kind::File);
                    }) as Box<Operation>,
                    Box::new(|volume: &mut Volume<'_, Device<'_>>| {
                        let root = volume.superblock().root;
                        let _ = volume.remove(root, b"brief");
                    }),
                ],
            ),
        ]
    }
}
