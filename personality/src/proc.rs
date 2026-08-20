// SPDX-License-Identifier: Apache-2.0
//! The `/proc` a hosted process may read about itself.
//!
//! [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md) step 10, and it
//! is decided by **one rule**: nothing here may name a Bhaskix object. Not a
//! domain id, not a capability slot, not a physical address, not an endpoint.
//! Everything a hosted program reads about itself is a number this personality
//! invented or a fact about its own memory.
//!
//! That rule is why the text lives here rather than in the adapter. A file
//! whose contents are generated where the capabilities are is a file one
//! careless interpolation away from leaking one; a file generated in a crate
//! that **has never seen a capability** cannot leak what it cannot name. The
//! test at the bottom is the rule made mechanical: it walks the generated text
//! and refuses any field name that is not on a list.
//!
//! ## Why these files
//!
//! `status` and `maps` are what a program actually reads about itself: a
//! runtime asks `status` for its own pid when it cannot trust `getpid` across
//! a `clone`, and `maps` is what every allocator, garbage collector and crash
//! handler walks to learn where its own memory is. `cmdline` and `environ`
//! wait for an `execve` that carries argv, which this personality does not yet
//! have — an empty file would be a lie, and a missing one is a refusal a
//! program can see.

use crate::process::Region;

/// Which synthetic file a descriptor names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum File {
    /// `/proc/self/status` — identity, as numbers this personality invented.
    Status,
    /// `/proc/self/maps` — what the process has mapped, in Linux's format.
    Maps,
}

impl File {
    /// The file a path names, or `None` if this personality has no such file.
    ///
    /// **Only `self`.** A hosted process reading `/proc/<pid>/` of *another*
    /// process is asking about somebody else, and answering would mean
    /// deciding whether it may — a permission question this personality has no
    /// answer for yet, and one that must be answered rather than assumed.
    /// **The path arrives as C sees it**: a buffer read out of the calling
    /// program's memory, with the name at the front, a `NUL` after it and
    /// whatever else was in that memory behind. Matching the whole buffer
    /// against a name is how the first version of this failed — it compared
    /// sixty-four bytes against six and never matched.
    #[must_use]
    pub fn from_path(path: &[u8]) -> Option<Self> {
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        let rest = strip(&path[..end], b"/proc/self/")?;
        match rest {
            b"status" => Some(Self::Status),
            b"maps" => Some(Self::Maps),
            _ => None,
        }
    }
}

/// Strips a prefix, answering the rest.
fn strip<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() < prefix.len() || &bytes[..prefix.len()] != prefix {
        return None;
    }
    Some(&bytes[prefix.len()..])
}

/// The most this personality will generate for one `/proc` file.
pub const MAX_BYTES: usize = 1024;

/// Writes `/proc/self/status`, and answers how many bytes it wrote.
///
/// **Every number here is the personality's own.** The pid and the parent's
/// come from the process record; the uid is Linux's arithmetic and confers
/// nothing. There is deliberately no field naming the domain, the CSpace, or
/// anything a capability could be reached through.
pub fn write_status(out: &mut [u8], pid: u32, ppid: u32, uid: u32) -> usize {
    let mut at = 0;
    at += put(out, at, b"Name:\thosted\n");
    at += put(out, at, b"State:\tR (running)\n");
    at += put(out, at, b"Pid:\t");
    at += decimal(out, at, u64::from(pid));
    at += put(out, at, b"\nPPid:\t");
    at += decimal(out, at, u64::from(ppid));
    at += put(out, at, b"\nUid:\t");
    for _ in 0..4 {
        at += decimal(out, at, u64::from(uid));
        at += put(out, at, b"\t");
    }
    at += put(out, at, b"\n");
    at
}

/// Writes `/proc/self/maps`, and answers how many bytes it wrote.
///
/// Linux's format, as far as a program parses it: `start-end perms offset dev
/// inode path`. The offset, device and inode are zeros — every region here is
/// anonymous, and a zero is what Linux itself writes for one. **A physical
/// address never appears**: these are the addresses the process asked for, in
/// its own space.
pub fn write_maps(out: &mut [u8], regions: &[Option<Region>], executable: u64) -> usize {
    let mut at = 0;
    for region in regions.iter().flatten() {
        if at + 80 > out.len() {
            break;
        }
        at += hex16(out, at, region.at);
        at += put(out, at, b"-");
        at += hex16(out, at, region.at + region.pages * 4096);
        at += put(out, at, b" ");
        at += put(out, at, permissions(region.protection, executable));
        at += put(out, at, b" 00000000 00:00 0 \n");
    }
    at
}

/// Linux's four permission characters for one region.
///
/// The protection word is the *kernel's* encoding, carried through the record
/// without this crate interpreting it — so the one value that matters,
/// read-execute, is named by the caller rather than assumed here.
fn permissions(protection: u64, executable: u64) -> &'static [u8; 4] {
    match protection {
        0 => b"---p",
        1 => b"r--p",
        _ if protection == executable => b"r-xp",
        _ => b"rw-p",
    }
}

/// Copies `bytes` into `out` at `at`, and answers how many landed.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    let take = bytes.len().min(out.len().saturating_sub(at));
    out[at..at + take].copy_from_slice(&bytes[..take]);
    take
}

/// Writes a decimal number, and answers its length.
fn decimal(out: &mut [u8], at: usize, mut value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut length = 0;
    loop {
        digits[length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut written = 0;
    for index in (0..length).rev() {
        written += put(out, at + written, &[digits[index]]);
    }
    written
}

/// Writes sixteen lowercase hexadecimal digits, as `maps` does.
fn hex16(out: &mut [u8], at: usize, value: u64) -> usize {
    let mut written = 0;
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as u8;
        let digit = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        written += put(out, at + written, &[digit]);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8], length: usize) -> &str {
        core::str::from_utf8(&bytes[..length]).expect("ascii")
    }

    #[test]
    fn status_names_the_pid_the_personality_invented() {
        let mut out = [0u8; MAX_BYTES];
        let length = write_status(&mut out, 7, 2, 0);
        let text = text(&out, length);
        assert!(text.contains("Pid:\t7\n"), "{text}");
        assert!(text.contains("PPid:\t2\n"), "{text}");
    }

    #[test]
    fn maps_writes_a_line_per_region_in_linuxs_shape() {
        let regions = [
            Some(Region {
                at: 0x5000_0000,
                pages: 1,
                protection: 3,
            }),
            Some(Region {
                at: 0x7000_0000,
                pages: 2,
                protection: 2,
            }),
            None,
        ];
        let mut out = [0u8; MAX_BYTES];
        let length = write_maps(&mut out, &regions, 3);
        let text = text(&out, length);
        assert!(
            text.contains("0000000050000000-0000000050001000 r-xp"),
            "{text}"
        );
        assert!(
            text.contains("0000000070000000-0000000070002000 rw-p"),
            "{text}"
        );
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn a_path_this_personality_does_not_serve_is_not_guessed_at() {
        assert_eq!(File::from_path(b"/proc/self/status"), Some(File::Status));
        assert_eq!(File::from_path(b"/proc/self/maps"), Some(File::Maps));
        assert_eq!(File::from_path(b"/proc/self/cmdline"), None);
        assert_eq!(File::from_path(b"/proc/1/status"), None, "somebody else");
        assert_eq!(File::from_path(b"/proc/self"), None);
        assert_eq!(File::from_path(b"status"), None);
        // As it actually arrives: a name, a `NUL`, and the rest of a buffer.
        let mut buffer = [0u8; 64];
        buffer[..15].copy_from_slice(b"/proc/self/maps");
        buffer[40] = b'x';
        assert_eq!(File::from_path(&buffer), Some(File::Maps));
    }

    /// **The leak test, and it is the reason this module exists.**
    ///
    /// Every field name in the generated text must be one of these. A field
    /// added later that named a domain, a capability slot or a physical
    /// address would fail here — which is a check a `grep` for known-bad
    /// strings could never be, because it enumerates what is *allowed* rather
    /// than guessing what is forbidden.
    #[test]
    fn nothing_in_proc_names_a_bhaskix_object() {
        const ALLOWED: [&str; 5] = ["Name", "State", "Pid", "PPid", "Uid"];

        let mut out = [0u8; MAX_BYTES];
        let length = write_status(&mut out, 7, 2, 0);
        for line in text(&out, length).lines() {
            let Some((field, _)) = line.split_once(':') else {
                continue;
            };
            assert!(
                ALLOWED.contains(&field),
                "`{field}` is not a field this personality may publish"
            );
        }

        // And `maps` carries no names at all: addresses in the process's own
        // space, permissions, and the zeros Linux writes for an anonymous
        // mapping. A path column would be the place a leak would appear, and
        // there is not one.
        let regions = [Some(Region {
            at: 0x5000_0000,
            pages: 1,
            protection: 2,
        })];
        let length = write_maps(&mut out, &regions, 3);
        let text = text(&out, length);
        assert!(
            !text.contains('/'),
            "a path column is where a leak would hide: {text}"
        );
        assert!(
            text.chars()
                .all(|c| c.is_ascii_hexdigit() || " -rwxp:\n0".contains(c) || c.is_ascii_digit()),
            "{text}"
        );
    }
}
