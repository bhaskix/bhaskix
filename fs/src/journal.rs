// SPDX-License-Identifier: Apache-2.0
//! The write-ahead log: [RFC 0015](../../docs/rfc/0015-filesystem.md) step 5.
//!
//! Every metadata change is written to a log, the log is committed with a
//! checksum, and only then does anything go where it belongs. On mount the log
//! is replayed. That is the whole mechanism, and it is old; what matters is
//! which claim it is being asked to support and where that claim can break.
//!
//! **The claim.** *After any interruption, the filesystem mounts, and every
//! operation acknowledged before the interruption is present.* Anything weaker
//! is not worth a journal. Anything stronger is not true without ordering the
//! data writes too, which this does not do.
//!
//! **Where the claim lives** is one instant: the write of the commit block.
//! Before it, the transaction does not exist and the filesystem is exactly
//! what it was. After it, the transaction is certain and replay will finish
//! it, however many times it takes. So "acknowledged" has a precise
//! definition here — the commit block was written — rather than the vague one
//! ("the call returned") that lets a filesystem be wrong and pass its tests.
//!
//! **What it rests on.** That a block write either happens or does not. Real
//! hardware promises that of a *sector*, not of a 4 KiB block, so the commit
//! block's meaning is carried entirely in its first sector: magic, sequence,
//! count and checksum are all inside the first 512 bytes, and the home-block
//! table that follows them is covered by that checksum. A commit block torn
//! halfway therefore fails its checksum and is ignored, which is the safe
//! direction — a transaction that was not certain is not applied.
//!
//! **Why replay can be run twice.** It copies bytes from the log to fixed
//! destinations. Running it again writes the same bytes to the same places, so
//! an interruption *during recovery* costs nothing but another recovery. This
//! is the property that makes the ordering below sufficient, and it is worth
//! naming because a journal whose replay were not idempotent would need a
//! second mechanism to protect the first.
//!
//! The order, then:
//!
//! 1. File data to its home, for a block being allocated. Not journalled —
//!    RFC 0015 says data is not — but written *before* the commit that
//!    references it, so a block that an inode claims has never been a block
//!    holding somebody else's bytes.
//! 2. Every changed metadata block into the log.
//! 3. The commit block. **This is the acknowledgement.**
//! 4. Each logged block to its home.
//! 5. The commit block cleared.
//!
//! An interruption in 1 or 2 leaves nothing committed. In 3, the checksum
//! fails and nothing is committed. In 4 or 5, the commit stands and replay
//! finishes the job. There is no sixth case, and the harness in
//! [`crate::volume`] proves it by stopping at every write in turn rather than
//! at one chosen point — a journal whose recovery has been tested at one
//! arbitrary place has been tested nowhere.

use crate::{BLOCK, FsError, Superblock, checksum, put, u32_at, u64_at};

/// How many blocks one transaction may change.
///
/// The journal's payload area, one block each. An operation that would need
/// more is refused before it starts: half of a change that does not fit is
/// worse than none of it.
pub const MAX_STAGED: usize = 8;

/// Where the home-block table starts in the commit block.
const TABLE: usize = 24;

/// What the commit block says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commit {
    /// Which transaction. Never zero when one is committed.
    pub sequence: u64,
    /// How many blocks it carries.
    pub count: u32,
}

/// Reads the commit block, if it holds a committed transaction.
///
/// `None` covers every way of not having one, and they are deliberately not
/// told apart: no magic, a failed checksum, a zero sequence, a count that will
/// not fit. Each means the same thing — there is nothing here that must be
/// applied — and a caller that could distinguish them would be tempted to
/// treat "damaged" differently from "absent", which is how a torn commit gets
/// replayed.
#[must_use]
pub fn committed(bytes: &[u8], superblock: &Superblock) -> Option<Commit> {
    let head = block_of(bytes, superblock.journal_start)?;
    if u64_at(head, 0)? != crate::JOURNAL_MAGIC {
        return None;
    }
    let sequence = u64_at(head, 8)?;
    let count = u32_at(head, 16)?;
    let stored = u32_at(head, 20)?;
    if sequence == 0 || count == 0 || count as usize > MAX_STAGED {
        return None;
    }
    if u64::from(count) >= superblock.journal_blocks {
        return None;
    }

    // The checksum covers the header, the table of destinations, *and* the
    // logged blocks themselves. Covering the header alone would let a
    // transaction commit over payload blocks that were never fully written --
    // which is precisely the interruption this is here to survive.
    if stored != transaction_checksum(bytes, superblock, count)? {
        return None;
    }
    Some(Commit { sequence, count })
}

/// Where the `index`th logged block goes.
fn home(bytes: &[u8], superblock: &Superblock, index: u32) -> Option<u32> {
    let head = block_of(bytes, superblock.journal_start)?;
    u32_at(head, TABLE + (index as usize) * 4)
}

/// The checksum a commit block should carry.
fn transaction_checksum(bytes: &[u8], superblock: &Superblock, count: u32) -> Option<u32> {
    let head = block_of(bytes, superblock.journal_start)?;
    // FNV-1a is a running hash, so the pieces are folded one after another
    // rather than copied into one buffer -- there is no buffer to copy into in
    // a filesystem that must work with no allocator.
    let mut hash = crate::checksum_of(0x811c_9dc5, head.get(..20)?);
    hash = crate::checksum_of(hash, head.get(TABLE..TABLE + count as usize * 4)?);
    for index in 0..count {
        let logged = block_of(bytes, superblock.journal_start + 1 + u64::from(index))?;
        hash = crate::checksum_of(hash, logged);
    }
    Some(if hash == 0 { 1 } else { hash })
}

/// One block of the image.
fn block_of(bytes: &[u8], index: u64) -> Option<&[u8]> {
    let at = usize::try_from(index).ok()?.checked_mul(BLOCK)?;
    bytes.get(at..at.checked_add(BLOCK)?)
}

/// Writes the commit block for a transaction whose payload is already in place.
///
/// Called only after every payload block has been written, because the
/// checksum is over them: writing this first would commit a transaction whose
/// contents were still arriving.
///
/// # Errors
///
/// [`FsError::OutOfRange`] if the image cannot hold the journal the superblock
/// describes, and [`FsError::Full`] for more blocks than the log has room for.
pub fn write_commit(
    bytes: &mut [u8],
    superblock: &Superblock,
    sequence: u64,
    homes: &[u32],
) -> Result<[u8; BLOCK], FsError> {
    if homes.is_empty() || homes.len() > MAX_STAGED {
        return Err(FsError::Full);
    }
    if u64::try_from(homes.len()).unwrap_or(u64::MAX) >= superblock.journal_blocks {
        return Err(FsError::Full);
    }

    let mut head = [0u8; BLOCK];
    put(&mut head, 0, &crate::JOURNAL_MAGIC.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    put(&mut head, 8, &sequence.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    put(&mut head, 16, &(homes.len() as u32).to_le_bytes()).ok_or(FsError::OutOfRange)?;
    for (index, block) in homes.iter().enumerate() {
        put(&mut head, TABLE + index * 4, &block.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    }

    // The checksum is computed against the image with this header in place,
    // which it is not yet -- so the header goes into a scratch block first,
    // the hash is folded over it and the payload, and the finished block is
    // what the caller writes. One write, and it is the commit.
    let at = usize::try_from(superblock.journal_start)
        .ok()
        .and_then(|start| start.checked_mul(BLOCK))
        .ok_or(FsError::OutOfRange)?;
    let mut hash = crate::checksum_of(0x811c_9dc5, &head[..20]);
    hash = crate::checksum_of(hash, &head[TABLE..TABLE + homes.len() * 4]);
    for index in 0..homes.len() {
        let logged = block_of(bytes, superblock.journal_start + 1 + index as u64)
            .ok_or(FsError::OutOfRange)?;
        hash = crate::checksum_of(hash, logged);
    }
    let hash = if hash == 0 { 1 } else { hash };
    put(&mut head, 20, &hash.to_le_bytes()).ok_or(FsError::OutOfRange)?;

    let _ = at;
    let _ = checksum;
    Ok(head)
}

/// Where the `index`th logged block is, and where it belongs.
///
/// # Errors
///
/// [`FsError::OutOfRange`] if either is outside the image.
pub fn logged(
    bytes: &[u8],
    superblock: &Superblock,
    index: u32,
) -> Result<(u32, [u8; BLOCK]), FsError> {
    let destination = home(bytes, superblock, index).ok_or(FsError::OutOfRange)?;
    // Every destination came off the disk. A log that named the superblock, or
    // a block past the end of the image, would be replayed straight over
    // them -- so the range is checked here, on the way out, rather than
    // trusted because it was written by this code the last time.
    if u64::from(destination) == 0 || u64::from(destination) >= superblock.blocks {
        return Err(FsError::OutOfRange);
    }
    let source = block_of(bytes, superblock.journal_start + 1 + u64::from(index))
        .ok_or(FsError::OutOfRange)?;
    let mut contents = [0u8; BLOCK];
    contents.copy_from_slice(source);
    Ok((destination, contents))
}
