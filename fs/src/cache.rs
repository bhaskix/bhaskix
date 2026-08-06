// SPDX-License-Identifier: Apache-2.0
//! Where blocks come from: [RFC 0015](../../docs/rfc/0015-filesystem.md) step 6.
//!
//! Until this step the filesystem was handed the whole image as one slice, and
//! every structure was read by indexing into it. That is only possible because
//! the image happened to be memory. A filesystem on a *disk* has no such slice;
//! it has a device it can ask for one block at a time, and somewhere to keep
//! the answers.
//!
//! So there are two things here, and keeping them apart is the point:
//!
//! - A [`Store`] is the device. Three methods, none of them clever: how many
//!   blocks, read one, write one. The block service is one; a byte array is
//!   another; the interruption harness is a third.
//! - [`Pages`] is where a block *is*, right now, as bytes. An [`Image`]
//!   answers by pointing into a slice it already has, and a [`Cache`] answers
//!   by looking, and going to the `Store` when it must.
//!
//! Everything that reads this filesystem reads it through `Pages`, and there
//! is exactly one implementation of "what an inode is" above that. Two readers
//! — one for images and one for devices — would be two chances to disagree
//! about the same bytes, and the disagreement would appear as a filesystem
//! that reads differently depending on where it lives.
//!
//! **The interruption lives in the `Store`.** Earlier steps announced writes
//! through a separate observer, which was one indirection away from the truth:
//! a write is interrupted at the device, not on the way to it. Now the harness
//! *is* a device that stops, and a trace is the sequence of writes the device
//! actually saw — which, with a cache in the way, is no longer the same as the
//! sequence of writes the filesystem asked for. That difference is what a
//! cache is, and it is why the journal has to say when a dirty page may go
//! home.

use crate::{BLOCK, FsError};

/// How many frames a cache can hold, at most.
///
/// The slot table is an array, so this is a compile-time ceiling rather than a
/// policy. A caller with fewer frames than this simply has fewer; one with
/// more gets this many, and the rest of its memory is not used — which is
/// better than a cache that silently indexes past its own table.
pub const MAX_FRAMES: usize = 64;

/// The fewest frames a cache can work with.
///
/// Two, because copying a block to another block needs both resident at once
/// and there is nowhere else to put one. Four is the practical floor for a
/// transaction that does not thrash; two is where it stops being *possible*,
/// and that is the number worth checking.
pub const MIN_FRAMES: usize = 2;

/// A block device, or something standing in for one.
///
/// Deliberately not `&mut [u8]`. The whole reason for this trait is that a
/// filesystem on a disk cannot be handed its own bytes, and a trait that could
/// be satisfied only by something holding them all would have changed nothing.
pub trait Store {
    /// How many blocks it holds.
    fn blocks(&self) -> u32;

    /// Reads one block.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] for a block it does not have.
    fn read(&mut self, block: u32, into: &mut [u8]) -> Result<(), FsError>;

    /// Writes one block.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] for a block it does not have, and
    /// [`FsError::Interrupted`] from a device that stopped — which is what the
    /// harness is.
    fn write(&mut self, block: u32, from: &[u8]) -> Result<(), FsError>;
}

/// Where a block is, as bytes, right now.
pub trait Pages {
    /// How many blocks there are in total.
    fn blocks(&self) -> u32;

    /// The bytes of `block`.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] for a block that does not exist, and anything
    /// the underlying store returns — including [`FsError::Interrupted`], because
    /// making room for a page may mean writing a dirty one out first.
    fn page(&mut self, block: u32) -> Result<&[u8], FsError>;
}

/// An image that is already memory.
///
/// The archive's copy of a filesystem is like this: it was read once at boot
/// and is simply there. A cache in front of it would copy bytes from memory to
/// memory to be able to find them again, which is work to no end.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
}

impl<'a> Image<'a> {
    /// Reads `bytes` as blocks.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl Pages for Image<'_> {
    fn blocks(&self) -> u32 {
        u32::try_from(self.bytes.len() / BLOCK).unwrap_or(u32::MAX)
    }

    fn page(&mut self, block: u32) -> Result<&[u8], FsError> {
        let at = (block as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        self.bytes
            .get(at..at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)
    }
}

/// A whole image in memory, as a `Store`.
///
/// What the host tests and `mkfs` use. It is not a cache and not a device; it
/// is the simplest thing that satisfies the trait, and having it means the
/// device-shaped code paths are exercised by every test rather than only by
/// the machine.
#[derive(Debug)]
pub struct Memory<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Memory<'a> {
    /// Treats `bytes` as a device.
    #[must_use]
    pub const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// The bytes, for a test that wants to look at the image directly.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl Store for Memory<'_> {
    fn blocks(&self) -> u32 {
        u32::try_from(self.bytes.len() / BLOCK).unwrap_or(u32::MAX)
    }

    fn read(&mut self, block: u32, into: &mut [u8]) -> Result<(), FsError> {
        let at = (block as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        let from = self
            .bytes
            .get(at..at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)?;
        into.get_mut(..BLOCK)
            .ok_or(FsError::OutOfRange)?
            .copy_from_slice(from);
        Ok(())
    }

    fn write(&mut self, block: u32, from: &[u8]) -> Result<(), FsError> {
        let at = (block as usize)
            .checked_mul(BLOCK)
            .ok_or(FsError::OutOfRange)?;
        let into = self
            .bytes
            .get_mut(at..at.checked_add(BLOCK).ok_or(FsError::OutOfRange)?)
            .ok_or(FsError::OutOfRange)?;
        into.copy_from_slice(from.get(..BLOCK).ok_or(FsError::OutOfRange)?);
        Ok(())
    }
}

/// What one frame is holding.
#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    /// The block it holds, if it holds one.
    block: Option<u32>,
    /// Whether it differs from what the store has.
    dirty: bool,
    /// When it was last wanted, for choosing what to evict.
    used: u64,
}

/// Blocks kept in frames, written back rather than written through.
///
/// **Write-back is the whole difficulty.** A dirty page is a change that has
/// been made and has not happened, and the journal is the only thing that
/// knows when it is allowed to happen: after the commit that describes it, and
/// before the commit is cleared. A write-through cache would need none of this
/// and would also make every metadata change a device write, which is the cost
/// the journal exists to avoid paying twice.
///
/// The frames are supplied rather than owned. In a machine they are the pages
/// of a `Memory` object, so that handing a reader a *capability to the cached
/// block* is possible at all — the alternative is copying the block to the
/// reader, which is the thing RFC 0015 says not to do.
pub struct Cache<'f, S: Store> {
    frames: &'f mut [u8],
    slots: [Slot; MAX_FRAMES],
    count: usize,
    clock: u64,
    store: S,
    /// How many pages were found already resident.
    hits: u64,
    /// How many had to be read from the store.
    misses: u64,
    /// How many were written back to it.
    written: u64,
}

impl<'f, S: Store> Cache<'f, S> {
    /// Caches `store` in `frames`.
    ///
    /// # Errors
    ///
    /// [`FsError::OutOfRange`] for fewer than [`MIN_FRAMES`] frames.
    pub fn new(frames: &'f mut [u8], store: S) -> Result<Self, FsError> {
        let count = (frames.len() / BLOCK).min(MAX_FRAMES);
        if count < MIN_FRAMES {
            return Err(FsError::OutOfRange);
        }
        Ok(Self {
            frames,
            slots: [Slot::default(); MAX_FRAMES],
            count,
            clock: 0,
            store,
            hits: 0,
            misses: 0,
            written: 0,
        })
    }

    /// Hits, misses, and write-backs so far.
    #[must_use]
    pub const fn counted(&self) -> (u64, u64, u64) {
        (self.hits, self.misses, self.written)
    }

    /// How many frames it has.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.count
    }

    /// The device underneath.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The bytes of one frame.
    fn frame(&self, slot: usize) -> &[u8] {
        let at = slot * BLOCK;
        &self.frames[at..at + BLOCK]
    }

    /// The bytes of one frame, to be changed.
    fn frame_mut(&mut self, slot: usize) -> &mut [u8] {
        let at = slot * BLOCK;
        &mut self.frames[at..at + BLOCK]
    }

    /// Which frame holds `block`, if any.
    fn resident(&self, block: u32) -> Option<usize> {
        self.slots[..self.count]
            .iter()
            .position(|slot| slot.block == Some(block))
    }

    /// Writes one frame back, if it needs it.
    fn write_back(&mut self, slot: usize) -> Result<(), FsError> {
        if !self.slots[slot].dirty {
            return Ok(());
        }
        let Some(block) = self.slots[slot].block else {
            return Ok(());
        };
        let at = slot * BLOCK;
        // Split rather than copy: the store is handed the frame itself. A
        // temporary would be four kilobytes of stack, which a kernel does not
        // have to spare and would need for no reason.
        let (frames, store) = (&self.frames[at..at + BLOCK], &mut self.store);
        store.write(block, frames)?;
        // Marked clean *after* the store accepted it. A device that refused
        // the write leaves the page dirty, so the next flush tries again --
        // and an interruption leaves it dirty, which is what makes the
        // recovery that follows have something to do.
        self.slots[slot].dirty = false;
        self.written += 1;
        Ok(())
    }

    /// Finds a frame for `block`, reading it in if it is not there.
    fn admit(&mut self, block: u32) -> Result<usize, FsError> {
        if u64::from(block) >= u64::from(self.store.blocks()) {
            return Err(FsError::OutOfRange);
        }
        if let Some(slot) = self.resident(block) {
            self.hits += 1;
            self.clock += 1;
            self.slots[slot].used = self.clock;
            return Ok(slot);
        }

        // The least recently wanted frame. An empty one first, because using
        // one costs nothing and evicting one costs a read later.
        let slot = self.slots[..self.count]
            .iter()
            .position(|slot| slot.block.is_none())
            .unwrap_or_else(|| {
                let mut oldest = 0;
                for (index, slot) in self.slots[..self.count].iter().enumerate() {
                    if slot.used < self.slots[oldest].used {
                        oldest = index;
                    }
                }
                oldest
            });

        // Evicting a dirty page writes it. That is a device write happening
        // because somebody read something else, which is worth stating: the
        // journal's ordering has to hold even when a write it did not ask for
        // happens between the ones it did.
        self.write_back(slot)?;

        let at = slot * BLOCK;
        let (frames, store) = (&mut self.frames[at..at + BLOCK], &mut self.store);
        store.read(block, frames)?;
        self.misses += 1;
        self.clock += 1;
        self.slots[slot] = Slot {
            block: Some(block),
            dirty: false,
            used: self.clock,
        };
        Ok(slot)
    }

    /// Replaces `block` entirely.
    ///
    /// Does not read it first: the caller is providing every byte, and reading
    /// a block that is about to be overwritten is the commonest wasted I/O a
    /// cache does.
    ///
    /// # Errors
    ///
    /// As [`Store::read`] and [`Store::write`] — making room may write a page.
    pub fn put(&mut self, block: u32, from: &[u8]) -> Result<(), FsError> {
        if u64::from(block) >= u64::from(self.store.blocks()) {
            return Err(FsError::OutOfRange);
        }
        let from = from.get(..BLOCK).ok_or(FsError::OutOfRange)?;
        let slot = match self.resident(block) {
            Some(slot) => {
                self.hits += 1;
                slot
            }
            None => {
                let slot = self.slots[..self.count]
                    .iter()
                    .position(|slot| slot.block.is_none())
                    .unwrap_or_else(|| {
                        let mut oldest = 0;
                        for (index, slot) in self.slots[..self.count].iter().enumerate() {
                            if slot.used < self.slots[oldest].used {
                                oldest = index;
                            }
                        }
                        oldest
                    });
                self.write_back(slot)?;
                slot
            }
        };
        self.frame_mut(slot).copy_from_slice(from);
        self.clock += 1;
        self.slots[slot] = Slot {
            block: Some(block),
            dirty: true,
            used: self.clock,
        };
        Ok(())
    }

    /// The bytes of `block`, to be changed.
    ///
    /// # Errors
    ///
    /// As [`Cache::page`].
    pub fn edit(&mut self, block: u32) -> Result<&mut [u8], FsError> {
        let slot = self.admit(block)?;
        self.slots[slot].dirty = true;
        Ok(self.frame_mut(slot))
    }

    /// Copies one block over another, without leaving the cache.
    ///
    /// # Errors
    ///
    /// As [`Cache::page`], and [`FsError::OutOfRange`] if both blocks cannot be
    /// resident at once — which needs two frames, and is why [`MIN_FRAMES`] is
    /// two.
    pub fn copy(&mut self, from: u32, to: u32) -> Result<(), FsError> {
        if from == to {
            return Ok(());
        }
        let source = self.admit(from)?;
        // Wanted *now*, so that admitting the destination does not choose the
        // source as the frame to evict. Without this the copy reads its own
        // source back from the store, and on a two-frame cache it would do
        // that every time.
        self.clock += 1;
        self.slots[source].used = self.clock;

        let destination = self.admit(to)?;
        if source == destination {
            return Err(FsError::OutOfRange);
        }

        let (low, high) = if source < destination {
            (source, destination)
        } else {
            (destination, source)
        };
        let (before, after) = self.frames.split_at_mut(high * BLOCK);
        let low = &mut before[low * BLOCK..low * BLOCK + BLOCK];
        let high = &mut after[..BLOCK];
        if source < destination {
            high.copy_from_slice(low);
        } else {
            low.copy_from_slice(high);
        }

        self.slots[destination].dirty = true;
        Ok(())
    }

    /// Writes every dirty page back.
    ///
    /// Returns how many went. This is the only way the filesystem says "now",
    /// and the journal is the only thing that says it.
    ///
    /// # Errors
    ///
    /// As [`Store::write`].
    pub fn flush(&mut self) -> Result<u32, FsError> {
        let mut went = 0;
        for slot in 0..self.count {
            if self.slots[slot].dirty {
                self.write_back(slot)?;
                went += 1;
            }
        }
        Ok(went)
    }

    /// Whether anything is waiting to be written.
    #[must_use]
    pub fn dirty(&self) -> bool {
        self.slots[..self.count].iter().any(|slot| slot.dirty)
    }

    /// Forgets everything, writing nothing.
    ///
    /// For a reader that wants to see what the *device* holds rather than what
    /// this cache remembers — which is how a test tells a write that happened
    /// from one that was only promised.
    pub fn forget(&mut self) {
        self.slots = [Slot::default(); MAX_FRAMES];
    }
}

impl<S: Store> Pages for Cache<'_, S> {
    fn blocks(&self) -> u32 {
        self.store.blocks()
    }

    fn page(&mut self, block: u32) -> Result<&[u8], FsError> {
        let slot = self.admit(block)?;
        Ok(self.frame(slot))
    }
}
