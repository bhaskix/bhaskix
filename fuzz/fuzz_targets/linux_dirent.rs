// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the Linux personality's directory encoder.
//!
//! RFC 0005 Tier 1, whose implementation plan makes a fuzz target mandatory
//! before the tier merges. This is it.
//!
//! **The untrusted input is the filesystem's, not the program's.** A hosted
//! `getdents64` hands its buffer to `bin/linuxd`, which fills it from names
//! the *filesystem* supplied — and a filesystem image is something a package
//! installs, a disk carries, or an attacker writes. So the interesting bytes
//! here are the names and the buffer size, and the property that matters is
//! that a caller walking the result the way a libc walks it can never step
//! outside what was written.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal — an empty name, a name
//! holding a separator or a NUL, and a buffer too small for one record are
//! all things `write_dirent` is supposed to say no to.
//!
//! Three properties are asserted rather than merely exercised:
//!
//! 1. **A record never claims more room than it was given.** `d_reclen` is
//!    the only thing a caller has to walk with; one that exceeded the bytes
//!    written would march the caller off the end of its own buffer, which is
//!    a read past the end of an allocation in every libc that has ever
//!    parsed this structure.
//! 2. **Walking the buffer the way a libc walks it reproduces exactly the
//!    names that went in, in order.** The walker below reads *only*
//!    `d_reclen` and the NUL terminator — it never calls `dirent_bytes` —
//!    so a padding rule the writer and the reader disagreed about shows up
//!    as a wrong name rather than as nothing at all.
//! 3. **`d_off` strictly increases.** A caller that seeks to the offset in
//!    the last record it read must not be handed that record again; equal or
//!    decreasing offsets are an infinite `readdir`.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run linux_dirent -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_personality::file::{DIRENT_HEADER_BYTES, dirent_bytes, dirent_type, write_dirent};

/// The buffer the records are written into. Larger than any single record,
/// so that "full" is reached by accumulating rather than only at the first.
const ROOM: usize = 512;

fuzz_target!(|data: &[u8]| {
    // The first byte chooses how much of the buffer the caller offers, so a
    // short buffer is reached by construction rather than by chance. This is
    // the disagreement that matters: what the writer wants and what the
    // caller gave.
    let (offered, names) = match data.split_first() {
        Some((first, rest)) => ((usize::from(*first) * 2).min(ROOM), rest),
        None => return,
    };

    // Names are the rest of the input split on `0xff`, which is not a byte
    // any of the refusals key on — so the split itself never decides whether
    // a name is legal.
    let mut buffer = [0u8; ROOM];
    let mut written = 0usize;
    let mut expected: [(&[u8], u64); 64] = [(&[], 0); 64];
    let mut count = 0usize;
    let mut offset = 0u64;

    for name in names.split(|byte| *byte == 0xff) {
        if count == expected.len() {
            break;
        }
        let kind = if offset % 2 == 0 {
            dirent_type::DIR
        } else {
            dirent_type::REG
        };
        match write_dirent(
            &mut buffer[written..offered],
            offset,
            offset + 1,
            kind,
            name,
        ) {
            Ok(bytes) => {
                // Property 1, at the moment of writing: what it says it took
                // is what it was allowed to take.
                assert_eq!(bytes, dirent_bytes(name.len()));
                assert!(written + bytes <= offered, "a record wrote past the offer");
                expected[count] = (name, offset + 1);
                count += 1;
                written += bytes;
                offset += 1;
            }
            Err(_) => {
                // A refusal must not have touched the buffer: the next
                // record still has to land where this one would have.
                continue;
            }
        }
    }

    // Now walk it the way a libc does: `d_reclen` and a NUL, nothing else.
    let mut at = 0usize;
    let mut seen = 0usize;
    let mut previous: Option<u64> = None;
    while at < written {
        assert!(
            written - at >= DIRENT_HEADER_BYTES + 1,
            "a partial record was left at the end of the buffer"
        );
        let record = &buffer[at..written];
        let reclen = usize::from(u16::from_le_bytes([record[16], record[17]]));

        // Property 1: the record fits in what was actually written.
        assert!(
            reclen >= DIRENT_HEADER_BYTES + 1,
            "a record shorter than its own header"
        );
        assert_eq!(
            reclen % 8,
            0,
            "a record a caller cannot walk in eight-byte steps"
        );
        assert!(
            reclen <= written - at,
            "d_reclen walks past the end of the buffer"
        );

        let inode = u64::from_le_bytes(record[0..8].try_into().unwrap());
        let d_off = u64::from_le_bytes(record[8..16].try_into().unwrap());

        // Property 3: offsets strictly increase.
        if let Some(last) = previous {
            assert!(d_off > last, "a listing that would be read for ever");
        }
        previous = Some(d_off);

        let name_bytes = &record[DIRENT_HEADER_BYTES..reclen];
        let end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .expect("every name is terminated");

        // Property 2: this is the name that went in, at this position.
        assert!(seen < count, "more records came out than went in");
        let (wanted, wanted_off) = expected[seen];
        assert_eq!(
            &name_bytes[..end],
            wanted,
            "a name changed on the way through"
        );
        assert_eq!(d_off, wanted_off);
        assert_eq!(inode, wanted_off - 1);

        seen += 1;
        at += reclen;
    }
    assert_eq!(seen, count, "a record that went in did not come out");
});
