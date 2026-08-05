// SPDX-License-Identifier: Apache-2.0
//! A read-only filesystem over the initial ramdisk.
//!
//! `docs/roadmap.md` M6 asks for "a VFS layer; a simple on-disk filesystem
//! (initially read-only, `initrd`-backed)". This is that layer, and it is
//! deliberately the smallest thing that deserves the name: paths resolve,
//! files open, reads advance a cursor, and a directory can be listed.
//!
//! # What a path is, and what it is not
//!
//! A path here is bytes, not text, and it names a member of a flat archive.
//! There is no current directory, no symlink, no mount table, and no `..`.
//!
//! `..` is **rejected** rather than resolved, which matters more than the flat
//! backing makes it look. Today it could not escape anything, because the
//! lookup is a string comparison against archive members. The moment a backend
//! resolves paths against a tree — which M6-06's block device will — a `..`
//! that was quietly accepted becomes a directory traversal, and the accepting
//! happened years earlier in a layer nobody rereads.
//!
//! [RFC 0003](../../../docs/rfc/0003-storage-architecture.md) argues at length
//! that POSIX is the wrong primitive for Bhaskix's storage. That argument is
//! about the *storage layer*; this is a personality over it, and a very small
//! one. Nothing below here knows what a path is.
//!
//! # What this is not
//!
//! - **Not writable.** Nothing here creates, truncates or appends.
//! - **Not shared.** A [`File`] is a cursor over a borrowed slice; two of them
//!   over the same member are independent and neither is visible to the other.
//! - **Not capability-scoped yet.** Opening a file needs no capability, so a
//!   domain that can reach this code can read the whole ramdisk.
//!   `docs/security.md` §2 says authority must be held rather than ambient,
//!   and this is a place where it is not. The kernel is the only caller today;
//!   before any domain reaches it, an open must take a capability.

use crate::ustar::{Archive, Entry, EntryKind};

/// Where the mounted archive lives.
///
/// A `static` rather than a handle passed around, because there is exactly one
/// filesystem and threading it through every caller would be ceremony. When
/// there are two, this becomes a mount table and the ceremony becomes real.
static mut ROOT: Option<&'static [u8]> = None;

/// Why an open failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VfsError {
    /// Nothing is mounted.
    NotMounted,
    /// No member of that name.
    NotFound,
    /// The path contained a component this layer refuses to interpret.
    BadPath,
    /// The name resolved to something that is not a readable file.
    NotAFile,
}

/// Mounts `bytes` as the root filesystem.
///
/// # Safety
///
/// Must be called once, before any other CPU can call into this module, with
/// a slice that lives for the rest of the kernel's life.
pub unsafe fn mount(bytes: &'static [u8]) {
    // SAFETY: the caller guarantees single-threaded initialisation.
    unsafe {
        ROOT = Some(bytes);
    }
}

fn root() -> Option<&'static [u8]> {
    // SAFETY: written once during boot, before any other CPU can reach it, and
    // never again.
    unsafe { ROOT }
}

/// Whether a path is one this layer will resolve.
///
/// Rejects `..` anywhere, an empty component, and anything containing a NUL.
/// Each is refused rather than normalised, because normalising is a decision
/// and a decision made here is one every backend inherits.
fn is_acceptable(path: &[u8]) -> bool {
    if path.is_empty() || path.contains(&0) {
        return false;
    }
    let trimmed = path.strip_prefix(b"/").unwrap_or(path);
    if trimmed.is_empty() {
        return false;
    }
    for component in trimmed.split(|byte| *byte == b'/') {
        if component == b".." || component.is_empty() {
            return false;
        }
    }
    true
}

/// The name a member is known by, with the archiver's decorations removed.
///
/// `tar -C dir .` writes `./etc/hostname`, and a directory is written with a
/// trailing separator: `./etc/`. Neither is part of the name — they are how
/// the archive spells "relative to here" and "this is a directory", and the
/// second is already in the type flag. Stripping both here means the whole
/// module compares names one way, which is the point: a lookup that matched
/// `etc/` and a listing that matched `etc` would disagree about whether a
/// directory exists.
fn member_name<'a>(entry: &Entry<'a>) -> &'a [u8] {
    let name = entry.name();
    let name = name.strip_prefix(b"./").unwrap_or(name);
    name.strip_suffix(b"/").unwrap_or(name)
}

/// Finds the member `path` names, whatever kind it is.
///
/// Pure, so it can be tested against an archive without mounting one — the
/// mount point is a `static`, and a test that had to install one could not run
/// beside another test that installed a different one.
fn resolve<'a>(bytes: &'a [u8], path: &[u8]) -> Option<Entry<'a>> {
    let wanted = path.strip_prefix(b"/").unwrap_or(path);
    Archive::new(bytes).find(|entry| member_name(entry) == wanted)
}

/// An open file: a borrowed slice and a position in it.
#[derive(Clone, Copy)]
pub struct File {
    data: &'static [u8],
    offset: usize,
}

impl File {
    /// The file's length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the file is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The whole file, ignoring the cursor.
    ///
    /// For a consumer that wants the bytes rather than a stream — the ELF
    /// loader, for one, which needs to look at a header and then at offsets it
    /// finds there.
    #[must_use]
    pub const fn bytes(&self) -> &'static [u8] {
        self.data
    }

    /// Where the cursor is.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Moves the cursor back to the start.
    pub const fn rewind(&mut self) {
        self.offset = 0;
    }

    /// Copies up to `buffer.len()` bytes from the cursor, and advances it.
    ///
    /// Returns how many were copied. Zero means end of file, and is not an
    /// error — a caller that treats a short read as a failure will be wrong
    /// the first time a file is not a multiple of its buffer.
    pub fn read(&mut self, buffer: &mut [u8]) -> usize {
        let remaining = self.data.len().saturating_sub(self.offset);
        let count = remaining.min(buffer.len());
        buffer[..count].copy_from_slice(&self.data[self.offset..self.offset + count]);
        self.offset += count;
        count
    }
}

/// Opens a file for reading.
///
/// # Errors
///
/// [`VfsError`] if nothing is mounted, the path is one this layer refuses, or
/// the name does not resolve to a file.
pub fn open(path: &[u8]) -> Result<File, VfsError> {
    let bytes = root().ok_or(VfsError::NotMounted)?;
    if !is_acceptable(path) {
        return Err(VfsError::BadPath);
    }

    let entry = resolve(bytes, path).ok_or(VfsError::NotFound)?;
    match entry.kind() {
        EntryKind::File => Ok(File {
            data: entry.data(),
            offset: 0,
        }),
        _ => Err(VfsError::NotAFile),
    }
}

/// Reads a whole file into `buffer`, returning its length.
///
/// # Errors
///
/// As [`open`]. A file longer than `buffer` is *not* an error: the length
/// returned is the file's, so a caller can tell truncation from a short file
/// by comparing it against what it asked for.
pub fn read_all(path: &[u8], buffer: &mut [u8]) -> Result<usize, VfsError> {
    let mut file = open(path)?;
    let length = file.len();
    file.read(buffer);
    Ok(length)
}

/// Runs `f` for every entry directly under `directory`.
///
/// `(name, kind, size)`, where the name is the component within the directory
/// rather than the whole path — the shape a listing wants. A `directory` of
/// `b""` lists the root.
///
/// Nested entries are skipped rather than flattened: a listing that showed
/// `etc/hostname` when asked for the root would be showing something that is
/// not there.
pub fn list(directory: &[u8], mut f: impl FnMut(&[u8], EntryKind, usize)) {
    let Some(bytes) = root() else {
        return;
    };

    let prefix = directory.strip_prefix(b"/").unwrap_or(directory);
    let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);

    for entry in Archive::new(bytes) {
        let name = member_name(&entry);
        if name.is_empty() {
            continue;
        }

        let relative = if prefix.is_empty() {
            name
        } else {
            match name.strip_prefix(prefix) {
                Some(rest) => match rest.strip_prefix(b"/") {
                    Some(rest) => rest,
                    None => continue,
                },
                None => continue,
            }
        };

        // Directly under, not anywhere below.
        if relative.is_empty() || relative.contains(&b'/') {
            continue;
        }

        f(relative, entry.kind(), entry.data().len());
    }
}

/// How many entries a directory holds.
#[must_use]
pub fn count(directory: &[u8]) -> usize {
    let mut total = 0;
    list(directory, |_, _, _| total += 1);
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_a_parent_component_is_refused() {
        // Refused rather than resolved. It cannot escape anything today,
        // because the backing is a flat archive and the lookup is a string
        // comparison. It becomes a traversal the moment a backend walks a
        // tree, and by then this decision is years old.
        for path in [
            b"..".as_slice(),
            b"../etc/hostname".as_slice(),
            b"etc/../../hostname".as_slice(),
            b"/etc/..".as_slice(),
        ] {
            assert!(!is_acceptable(path), "{path:?} was accepted");
        }
    }

    #[test]
    fn an_empty_or_doubled_separator_is_refused() {
        for path in [
            b"".as_slice(),
            b"/".as_slice(),
            b"etc//hostname".as_slice(),
            b"/etc/".as_slice(),
        ] {
            assert!(!is_acceptable(path), "{path:?} was accepted");
        }
    }

    #[test]
    fn a_path_containing_a_nul_is_refused() {
        // A name is bytes, and a consumer that later hands it to something
        // expecting a C string would truncate at the NUL — so two different
        // paths would name the same file.
        assert!(!is_acceptable(b"etc/host\0name"));
    }

    #[test]
    fn ordinary_paths_are_accepted_with_or_without_a_leading_slash() {
        for path in [
            b"hello.txt".as_slice(),
            b"/hello.txt".as_slice(),
            b"etc/hostname".as_slice(),
            b"/etc/hostname".as_slice(),
        ] {
            assert!(is_acceptable(path), "{path:?} was refused");
        }
    }

    /// The archive `tar -C initrd .` produces, in miniature.
    fn sample() -> alloc::vec::Vec<u8> {
        crate::ustar::tests::archive_of(&[
            (b"./", b"", b'5'),
            (b"./hello.txt", b"hello\n", b'0'),
            (b"./etc/", b"", b'5'),
            (b"./etc/hostname", b"bhaskix\n", b'0'),
            (b"./bin/", b"", b'5'),
            (b"./bin/probe", b"\x7fELF", b'0'),
        ])
    }

    #[test]
    fn a_name_resolves_with_or_without_the_archivers_decorations() {
        // `./` on every member and a trailing `/` on directories are how the
        // archive spells "relative to here" and "this is a directory". Neither
        // is part of the name, and a lookup that thought otherwise would find
        // `etc/` and miss `etc`.
        let bytes = sample();
        for path in [b"etc".as_slice(), b"/etc".as_slice()] {
            let entry = resolve(&bytes, path).expect("etc");
            assert_eq!(entry.kind(), EntryKind::Directory);
        }
        assert!(resolve(&bytes, b"etc/hostname").is_some());
        assert!(resolve(&bytes, b"etc/").is_none(), "the name has no slash");
        assert!(resolve(&bytes, b"hostname").is_none(), "not at the root");
    }

    #[test]
    fn a_listing_shows_what_is_directly_under_a_directory_and_nothing_below() {
        let bytes = sample();
        // SAFETY: single-threaded test process, and every test that mounts
        // mounts an archive with these same members.
        unsafe { mount(alloc::boxed::Box::leak(bytes.into_boxed_slice())) };

        let mut names = alloc::vec::Vec::new();
        list(b"", |name, _, _| names.push(name.to_vec()));
        names.sort();
        assert_eq!(
            names,
            [b"bin".to_vec(), b"etc".to_vec(), b"hello.txt".to_vec()],
            "etc/hostname is below the root, not in it"
        );

        assert_eq!(count(b"etc"), 1);
        assert_eq!(
            count(b"/etc/"),
            1,
            "a trailing separator names the same thing"
        );
        assert_eq!(count(b"bin"), 1);
        assert_eq!(count(b"nowhere"), 0);
    }

    #[test]
    fn opening_a_directory_is_refused_rather_than_returning_nothing() {
        // A caller that got an empty file back would read zero bytes and
        // conclude the file was empty, which is a different fact.
        let bytes = sample();
        assert_eq!(
            resolve(&bytes, b"etc").map(|entry| entry.kind()),
            Some(EntryKind::Directory)
        );
    }

    #[test]
    fn a_cursor_advances_and_stops_at_the_end() {
        let mut file = File {
            data: b"abcdef",
            offset: 0,
        };
        let mut buffer = [0u8; 4];

        assert_eq!(file.read(&mut buffer), 4);
        assert_eq!(&buffer, b"abcd");
        assert_eq!(file.position(), 4);

        assert_eq!(file.read(&mut buffer), 2, "a short read is not an error");
        assert_eq!(&buffer[..2], b"ef");

        assert_eq!(file.read(&mut buffer), 0, "end of file reads zero");
        file.rewind();
        assert_eq!(file.read(&mut buffer), 4);
    }

    #[test]
    fn reading_into_an_empty_buffer_copies_nothing_and_moves_nothing() {
        let mut file = File {
            data: b"abc",
            offset: 0,
        };
        assert_eq!(file.read(&mut []), 0);
        assert_eq!(file.position(), 0);
    }
}
