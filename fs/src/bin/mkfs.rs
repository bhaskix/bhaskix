// SPDX-License-Identifier: Apache-2.0
//! Builds a filesystem image, on the machine you are sitting at.
//!
//! [RFC 0015](../../../docs/rfc/0015-filesystem.md) step 2. The cost of a
//! format this project defines is that nothing else can read the disk — and
//! the first thing that costs is having no way to make one. So this is part of
//! the work rather than an extra.
//!
//! ```text
//! mkfs <image> <blocks> [name=file]...
//! ```
//!
//! Files named on the command line are copied into the root directory, which
//! is what makes an image worth booting rather than merely valid.

// This is a developer's tool, run on a developer's machine. The panic bans
// exist to stop a fallible operation taking down the nucleus; here, failing
// loudly with a message is the entire user interface.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;

use bhaskix_fs::{BLOCK, Bitmap, ENTRY, Entry, Inode, Kind, format};

fn main() {
    let mut arguments = std::env::args().skip(1);
    let (Some(path), Some(blocks)) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: mkfs <image> <blocks> [name=file]...");
        std::process::exit(2);
    };
    let blocks: usize = blocks.parse().expect("a number of blocks");
    assert!(blocks >= 8, "a filesystem needs more than {blocks} blocks");

    let mut bytes = vec![0u8; blocks * BLOCK];
    let superblock = format(&mut bytes, 128).expect("the image is large enough");

    // Whatever was asked for, into the root.
    let mut entries: Vec<Entry> = Vec::new();
    let mut next_inode = superblock.root + 1;
    for argument in arguments {
        let (name, source) = argument
            .split_once('=')
            .expect("arguments are name=file after the block count");
        let contents = std::fs::read(source).expect("the file exists");

        let mut direct = [0u32; 10];
        let mut written = 0usize;
        {
            let mut bitmap = Bitmap::of(&mut bytes, &superblock)
                .expect("the bitmap is where the superblock says");
            for slot in &mut direct {
                if written >= contents.len() {
                    break;
                }
                *slot = u32::try_from(bitmap.allocate().expect("a free block")).unwrap();
                written += BLOCK;
            }
        }
        assert!(
            written >= contents.len(),
            "{name} needs more than ten blocks, and this tool has no indirect block yet"
        );

        let mut left = &contents[..];
        for slot in direct.iter().take_while(|slot| **slot != 0) {
            let at = *slot as usize * BLOCK;
            let take = left.len().min(BLOCK);
            bytes[at..at + take].copy_from_slice(&left[..take]);
            left = &left[take..];
        }

        let inode = Inode {
            kind: Kind::File,
            links: 1,
            generation: 1,
            size: contents.len() as u64,
            direct,
            indirect: 0,
        };
        inode
            .write(&mut bytes, &superblock, next_inode)
            .expect("room in the table");
        entries.push(Entry::new(next_inode, name.as_bytes()).expect("a usable name"));
        next_inode += 1;
    }

    // The root's own block, holding the entries.
    if !entries.is_empty() {
        let block = {
            let mut bitmap = Bitmap::of(&mut bytes, &superblock).expect("the bitmap");
            bitmap.allocate().expect("a free block for the root")
        };
        let at = usize::try_from(block).unwrap() * BLOCK;
        assert!(
            entries.len() * ENTRY <= BLOCK,
            "more entries than one block holds, and this tool writes one"
        );
        for (which, entry) in entries.iter().enumerate() {
            entry
                .write(&mut bytes[at..at + BLOCK], which * ENTRY)
                .expect("inside the block");
        }

        let mut direct = [0u32; 10];
        direct[0] = u32::try_from(block).unwrap();
        let root = Inode {
            kind: Kind::Directory,
            links: 1,
            generation: 1,
            size: (entries.len() * ENTRY) as u64,
            direct,
            indirect: 0,
        };
        root.write(&mut bytes, &superblock, superblock.root)
            .expect("the root");
    }

    let mut file = std::fs::File::create(&path).expect("the image can be written");
    file.write_all(&bytes).expect("the image is written");
    println!(
        "built {path}: {blocks} blocks, {} entries in the root",
        entries.len()
    );
}
