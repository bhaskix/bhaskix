// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the on-disk filesystem — a hostile disk image.
//!
//! **The debt this pays.** `docs/coding-style.md` §8 and `security.md` §5 both
//! bind this project to a fuzz target *before* a parser touching untrusted
//! input merges. `bhaskix-fs` merged without one and stayed without one through
//! RFC 0015 and RFC 0016, while ELF, `ustar`, both package formats and every
//! network parser got theirs. The gap was found by the security reassessment of
//! 2026-08-20 and recorded as gap 5. This is it.
//!
//! **Why it matters more than its ranking suggests.** Journal replay is the
//! code that runs *before* anything can refuse: `Volume::mount` recovers a
//! committed transaction by copying logged blocks over their home locations,
//! and every destination in that table came off the disk. `fs/src/lib.rs`'s own
//! comment says the quiet part — *"a log that named the superblock, or a block
//! past the end of the filesystem, would be replayed straight over them"*.
//!
//! # Three arms, because one of them would find almost nothing
//!
//! **Arm A — raw bytes.** `Filesystem::mount` over whatever the fuzzer sends.
//! This is the honest baseline and it is also nearly useless on its own: a
//! superblock carries a magic, a version and an FNV-1a checksum, so random
//! bytes are refused at the first check and the fuzzer never reaches an inode,
//! a directory entry or a bitmap. **A target that only did this would report
//! millions of executions and have exercised one function.** It stays because
//! garbage is what a corrupted disk actually looks like, and because it is the
//! arm that proves the refusal itself does not panic.
//!
//! **Arm B — a valid image with attacker-chosen geometry.** Format a real
//! image, overwrite the superblock's *fields* from fuzzer bytes, and write it
//! back — which recomputes the checksum. Every one of those fields is used as
//! an index later, which is why `Superblock::read_head` sanity-checks them and
//! why this arm exists to attack those checks rather than the checksum.
//!
//! **Recomputing the checksum is deliberate and is not cheating.** A checksum
//! defends against corruption, not against somebody who can write a disk: an
//! attacker handing you an image computes a valid one. Arm B is the threat
//! model; arm A is the accident.
//!
//! **Arm C — a valid superblock over hostile contents.** Format, then splice
//! fuzzer bytes over everything after block 0. The geometry is sane, so the
//! free bitmap and the journal's commit block are read from fuzzer bytes, and
//! this is the arm that reaches `journal::home` — the function that takes a
//! replay destination off the disk.
//!
//! **Arm D — valid inodes with attacker-chosen contents, and it exists because
//! arms A to C were measured and found not to reach the walkers.** Inodes carry
//! a checksum too, so arm C's random bytes never decode: probing this harness
//! by panicking inside `Filesystem::list`'s callback ran **16,132 executions
//! without ever yielding a directory entry**. The superblock's checksum wall
//! had been climbed and the inode's had not, one level down.
//!
//! So arm D builds a populated image — a root directory with entries and a file
//! with block pointers — then takes the fuzzer's bytes as the inode's *fields*
//! and **re-encodes**, which recomputes the inode checksum. That puts
//! attacker-chosen block pointers, sizes and kinds behind a valid checksum,
//! which is the bug class that matters: a pointer that came off the disk and
//! was followed. The directory's data block is fuzzer bytes too, so `Entry`
//! decoding runs on hostile input rather than on zeros.
//!
//! **Every arm here was probed the same way before being believed.** A target
//! that compiles and reports a large execution count while never leaving the
//! first refusal is the normal failure of on-disk-format fuzzing, and counting
//! executions does not detect it.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal, and not a nonsense answer.
//! Random bytes are not a filesystem, and `NotAFilesystem` is the correct
//! reply. What must never happen is an index out of bounds, an offset that
//! wraps, a directory walk that does not terminate, or a read that hands back
//! bytes from outside the image.
//!
//! `bhaskix-fs` carries `#![forbid(unsafe_code)]` as of 2026-08-21, so a slice
//! out of bounds here is a panic rather than a silent read of adjacent memory —
//! which is exactly the property that makes a panic worth fuzzing for.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run fs_image -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_fs::{
    BLOCK, Entry, Filesystem, Free, Inode, Kind, Superblock, cache::Image, format, journal,
};

/// The scratch image arms B and C build on.
///
/// Sixty-four blocks: comfortably above `format`'s minimum of `4 +
/// JOURNAL_BLOCKS`, and small enough that a fuzzer mutating the body is
/// changing a large fraction of it on every pass rather than nudging one byte
/// of a megabyte.
const BLOCKS: usize = 64;
const IMAGE: usize = BLOCKS * BLOCK;

/// How many bytes of the input steer the geometry in arm B.
///
/// Eight `u64` fields and one `u32`, little-endian, taken from the front.
const CONTROL: usize = 8 * 7 + 4;

fuzz_target!(|data: &[u8]| {
    arm_a(data);
    arm_b(data);
    arm_c(data);
    arm_d(data);
});

/// Whatever the fuzzer sent, read as an image.
fn arm_a(data: &[u8]) {
    let mut image = Image::new(data);
    if let Ok(mut fs) = Filesystem::mount(&mut image) {
        walk(&mut fs);
    }

    // The lower parsers directly, because arm A almost never gets past the
    // superblock and these are what a caller reaches once it has.
    let _ = Superblock::read(data);
    let _ = Entry::read(data, 0);
    let _ = Entry::read(data, data.len().saturating_sub(1));
    let _ = Inode::decode(data);
}

/// A checksum-valid superblock whose geometry the fuzzer chose.
fn arm_b(data: &[u8]) {
    if data.len() < CONTROL {
        return;
    }
    let mut bytes = vec![0u8; IMAGE];
    let Ok(mut superblock) = format(&mut bytes, 32) else {
        return;
    };

    let word = |index: usize| -> u64 {
        let at = index * 8;
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&data[at..at + 8]);
        u64::from_le_bytes(buffer)
    };
    superblock.blocks = word(0);
    superblock.inodes = word(1);
    superblock.bitmap_start = word(2);
    superblock.inode_start = word(3);
    superblock.journal_start = word(4);
    superblock.journal_blocks = word(5);
    superblock.data_start = word(6);
    superblock.root = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);

    // `write` recomputes the checksum, which is the point of this arm: the
    // fields reach `read_head`'s validation rather than dying at the sum.
    if superblock.write(&mut bytes).is_err() {
        return;
    }

    let mut image = Image::new(&bytes);
    match Filesystem::mount(&mut image) {
        Ok(mut fs) => walk(&mut fs),
        Err(_) => {
            // Refused — by the checksum, by a field check, or by a pending
            // journal. Drive the walkers anyway through `using`, which is the
            // door `Volume` comes through after it has recovered, and which
            // therefore trusts a superblock this harness controls.
            if let Ok(parsed) = Superblock::read_head(&bytes[..BLOCK], BLOCKS as u64) {
                let mut image = Image::new(&bytes);
                let mut fs = Filesystem::using(&mut image, parsed);
                walk(&mut fs);
            }
        }
    }
}

/// A sane superblock over contents the fuzzer wrote.
fn arm_c(data: &[u8]) {
    let mut bytes = vec![0u8; IMAGE];
    if format(&mut bytes, 32).is_err() {
        return;
    }

    // Everything after the superblock: the bitmap, the inode table, the
    // journal's commit block and its destination table, and the data blocks.
    let body = &mut bytes[BLOCK..];
    for (slot, byte) in body.iter_mut().zip(data.iter().cycle()) {
        *slot = *byte;
    }

    let Ok(superblock) = Superblock::read_head(&bytes[..BLOCK], BLOCKS as u64) else {
        return;
    };

    // The journal, first and explicitly. `mount` refuses an image with a
    // committed transaction, so reaching `home` — which reads a destination
    // block number off the disk — means asking for it.
    {
        let mut image = Image::new(&bytes);
        if journal::committed(&mut image, &superblock).is_ok() {
            for index in 0..16 {
                let _ = journal::home(&mut image, &superblock, index);
            }
        }
    }

    {
        let mut image = Image::new(&bytes);
        let _ = Free::of(&bytes, &superblock);
        match Filesystem::mount(&mut image) {
            Ok(mut fs) => walk(&mut fs),
            Err(_) => {
                let mut image = Image::new(&bytes);
                let mut fs = Filesystem::using(&mut image, superblock);
                walk(&mut fs);
            }
        }
    }
}

/// A populated image whose inodes are hostile but checksum-valid.
///
/// The arm that actually reaches the walkers. See the module comment: without
/// it, `Filesystem::list` never yields an entry, because an inode built from
/// random bytes fails its own checksum before the walker sees a block pointer.
fn arm_d(data: &[u8]) {
    if data.len() < 16 {
        return;
    }
    let mut bytes = vec![0u8; IMAGE];
    let Ok(superblock) = format(&mut bytes, 32) else {
        return;
    };

    // A directory whose data block is the first data block, and a file after
    // it. Written through the crate's own encoder, so both checksums are real.
    let directory_block = u32::try_from(superblock.data_start).unwrap_or(0);
    let mut direct = [0u32; 10];
    direct[0] = directory_block;
    // Block pointers the fuzzer chose, behind a checksum it did not have to
    // forge. Two of them, so an image can name one valid and one wild block.
    direct[1] = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    direct[2] = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let root = Inode {
        kind: Kind::Directory,
        links: 1,
        generation: 1,
        // A size the fuzzer picked: `list` walks `size / ENTRY` entries, so
        // this is the loop bound an attacker controls.
        size: u64::from(u32::from_le_bytes([data[8], data[9], data[10], data[11]])),
        direct,
        indirect: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    };
    if root.write(&mut bytes, &superblock, 0).is_err() {
        return;
    }

    // The directory's own data block, and everything after it, is fuzzer
    // bytes — so `Entry` decoding runs on hostile input rather than on zeros.
    let at = (directory_block as usize) * BLOCK;
    if let Some(tail) = bytes.get_mut(at..) {
        for (slot, byte) in tail.iter_mut().zip(data.iter().cycle()) {
            *slot = *byte;
        }
    }

    // A second inode, so `walk`'s loop has more than one thing to decode.
    let second = Inode {
        kind: Kind::File,
        links: 1,
        generation: 2,
        size: u64::from(u32::from_le_bytes([data[8], data[9], data[10], data[11]])),
        direct,
        indirect: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    };
    let _ = second.write(&mut bytes, &superblock, 1);

    let mut image = Image::new(&bytes);
    match Filesystem::mount(&mut image) {
        Ok(mut fs) => walk(&mut fs),
        Err(_) => {
            let mut image = Image::new(&bytes);
            let mut fs = Filesystem::using(&mut image, superblock);
            walk(&mut fs);
        }
    }
}

/// What a caller does with a mounted filesystem.
///
/// Reading an inode without reading its *contents* proves half of it: the bug
/// that matters is a block pointer that came off the disk and is followed.
fn walk<P: bhaskix_fs::cache::Pages>(fs: &mut Filesystem<'_, P>) {
    // Every inode the superblock claims, bounded: the count is attacker-chosen
    // in arm B, and this harness is not a hang detector for its own loops.
    const MAX_INODES: u32 = 256;

    let limit = u32::try_from(fs.superblock().inodes).unwrap_or(MAX_INODES);
    for index in 0..limit.min(MAX_INODES) {
        let Ok(inode) = fs.inode(index) else { continue };

        let mut buffer = [0u8; 512];
        let _ = fs.read(&inode, 0, &mut buffer);
        // Past the end, and at an offset chosen to cross an indirect boundary.
        let _ = fs.read(&inode, u64::MAX - 1, &mut buffer);
        let _ = fs.read(&inode, BLOCK as u64 * 12, &mut buffer);

        let mut entries = 0usize;
        fs.list(&inode, |entry| {
            let _ = entry.name();
            entries += 1;
        });
        let _ = fs.lookup(&inode, b"bin");
        let _ = fs.lookup(&inode, b"");
    }

    if let Ok(root) = fs.root() {
        fs.list(&root, |entry| {
            let _ = entry.name();
        });
        let _ = fs.lookup(&root, b"etc");
    }
}
