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
//! it, however many times it takes. So "acknowledged" has a precise definition
//! here — the commit block reached the device — rather than the vague one
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
//! The order — and since step 6 put a cache in the way, "written" below means
//! *reached the device*, which is a flush and not an assignment:
//!
//! 1. File data to its home, for a block being allocated. Not journalled —
//!    RFC 0015 says data is not — but on the device before the commit that
//!    references it, so a block an inode claims has never been a block holding
//!    somebody else\'s bytes.
//! 2. Every changed metadata block into the log, and flushed.
//! 3. The commit block. **This is the acknowledgement.**
//! 4. Each logged block to its home, and flushed — *before* the log is
//!    cleared, which is the ordering the cache introduced and the only one
//!    here that is not obvious.
//! 5. The commit block cleared.

use crate::{FsError, Pages, Superblock, put, u32_at, u64_at};

/// How many blocks one transaction may change.
///
/// The journal\'s payload area, one block each. An operation that would need
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
///
/// # Errors
///
/// As [`Pages::page`].
pub fn committed<P: Pages>(
    pages: &mut P,
    superblock: &Superblock,
) -> Result<Option<Commit>, FsError> {
    let start = u32::try_from(superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
    let head = pages.page(start)?;
    let (Some(magic), Some(sequence), Some(count)) =
        (u64_at(head, 0), u64_at(head, 8), u32_at(head, 16))
    else {
        return Ok(None);
    };
    if magic != crate::JOURNAL_MAGIC
        || sequence == 0
        || count == 0
        || count as usize > MAX_STAGED
        || u64::from(count) >= superblock.journal_blocks
    {
        return Ok(None);
    }

    // The checksum covers the header, the table of destinations, *and* the
    // logged blocks themselves. Covering the header alone would let a
    // transaction commit over payload blocks that were never fully written --
    // which is precisely the interruption this is here to survive.
    let expected = transaction_checksum(pages, superblock, count)?;
    let head = pages.page(start)?;
    if u32_at(head, 20) != Some(expected) {
        return Ok(None);
    }
    Ok(Some(Commit { sequence, count }))
}

/// Whether a committed transaction is waiting.
///
/// # Errors
///
/// As [`Pages::page`].
pub fn pending<P: Pages>(pages: &mut P, superblock: &Superblock) -> Result<bool, FsError> {
    Ok(committed(pages, superblock)?.is_some())
}

/// The checksum a commit block should carry.
fn transaction_checksum<P: Pages>(
    pages: &mut P,
    superblock: &Superblock,
    count: u32,
) -> Result<u32, FsError> {
    let start = u32::try_from(superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
    // FNV-1a is a running hash, so the pieces are folded one after another
    // rather than copied into one buffer -- there is no buffer to copy into in
    // a filesystem that must work with no allocator. With pages that matters
    // for a second reason: on a small cache the header and the payload are
    // never resident together, so a hash that needed them at once could not be
    // computed at all.
    let head = pages.page(start)?;
    let mut hash = crate::checksum_of(0x811c_9dc5, head.get(..20).ok_or(FsError::OutOfRange)?);
    hash = crate::checksum_of(
        hash,
        head.get(TABLE..TABLE + count as usize * 4)
            .ok_or(FsError::OutOfRange)?,
    );
    for index in 0..count {
        let logged = pages.page(start + 1 + index)?;
        hash = crate::checksum_of(hash, logged);
    }
    Ok(if hash == 0 { 1 } else { hash })
}

/// How many bytes of a commit block actually say anything.
///
/// The header and the table of destinations. Everything after it is zero, and
/// building only this much is what keeps a transaction off the stack: a
/// `[u8; BLOCK]` here is four kilobytes per commit, and a kernel thread that
/// paid it twice per transaction ran off the end of its stack — which is a
/// page fault at an address in the stack area, and looks like nothing at all
/// until the numbers are read.
pub const HEAD: usize = TABLE + MAX_STAGED * 4;

/// Builds the commit block for a transaction whose payload is already in place.
///
/// Returns only the bytes that matter — see [`HEAD`]. The caller zeroes the
/// page and copies these in, which it can do through the cache without a
/// buffer of its own.
///
/// Called only after every payload block has reached the device, because the
/// checksum is over them: committing first would commit a transaction whose
/// contents were still arriving.
///
/// # Errors
///
/// [`FsError::Full`] for more blocks than the log has room for, and as
/// [`Pages::page`].
pub fn build_commit<P: Pages>(
    pages: &mut P,
    superblock: &Superblock,
    sequence: u64,
    homes: &[u32],
) -> Result<[u8; HEAD], FsError> {
    if homes.is_empty() || homes.len() > MAX_STAGED {
        return Err(FsError::Full);
    }
    if u64::try_from(homes.len()).unwrap_or(u64::MAX) >= superblock.journal_blocks {
        return Err(FsError::Full);
    }

    let mut head = [0u8; HEAD];
    put(&mut head, 0, &crate::JOURNAL_MAGIC.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    put(&mut head, 8, &sequence.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    put(&mut head, 16, &(homes.len() as u32).to_le_bytes()).ok_or(FsError::OutOfRange)?;
    for (index, block) in homes.iter().enumerate() {
        put(&mut head, TABLE + index * 4, &block.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    }

    let start = u32::try_from(superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
    let mut hash = crate::checksum_of(0x811c_9dc5, &head[..20]);
    hash = crate::checksum_of(hash, &head[TABLE..TABLE + homes.len() * 4]);
    for index in 0..homes.len() {
        let logged = pages.page(start + 1 + index as u32)?;
        hash = crate::checksum_of(hash, logged);
    }
    let hash = if hash == 0 { 1 } else { hash };
    put(&mut head, 20, &hash.to_le_bytes()).ok_or(FsError::OutOfRange)?;
    Ok(head)
}

/// Where the `index`th logged block belongs.
///
/// # Errors
///
/// [`FsError::OutOfRange`] if the destination is outside the filesystem.
pub fn home<P: Pages>(pages: &mut P, superblock: &Superblock, index: u32) -> Result<u32, FsError> {
    let start = u32::try_from(superblock.journal_start).map_err(|_| FsError::OutOfRange)?;
    let head = pages.page(start)?;
    let destination = u32_at(head, TABLE + (index as usize) * 4).ok_or(FsError::OutOfRange)?;
    // Every destination came off the disk. A log that named the superblock, or
    // a block past the end of the filesystem, would be replayed straight over
    // them -- so the range is checked here, on the way out, rather than trusted
    // because it was written by this code the last time.
    if destination == 0 || u64::from(destination) >= superblock.blocks {
        return Err(FsError::OutOfRange);
    }
    Ok(destination)
}
