// SPDX-License-Identifier: Apache-2.0
//! Descriptors, and the structures Linux passes them through.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md)'s Tier 1 and
//! Tier 2 both stand on one thing this system does not have: a **file
//! descriptor**. A socket is a descriptor, an `epoll` set is a descriptor,
//! and `epoll_ctl` names what it watches by descriptor — so the table below
//! is Tier 2's prerequisite as much as Tier 1's, which is why it is here
//! rather than waiting for the tier it is named after.
//!
//! **A descriptor is not authority, and that distinction is the whole
//! design.** What a table entry holds is a *handle*: a number the adapter
//! chose, which it can look up in whatever it keeps its capabilities in.
//! This crate never sees a capability, cannot derive one, and has no way to
//! turn a descriptor into one — the same charter every other module here
//! keeps. What it does own is the part Linux specifies exactly and a
//! translator gets subtly wrong: which number a new descriptor gets, what
//! `dup3` means when the two numbers are equal, and what a closed
//! descriptor answers.
//!
//! ## Where the layouts come from
//!
//! `struct stat`, `struct dirent64` and the flag values below were taken
//! **from this machine's own headers** — a program compiled against
//! `<sys/stat.h>`, `<dirent.h>` and `<fcntl.h>` printing `offsetof` and
//! `sizeof` — and not from memory. A personality is a promise about byte
//! offsets; recalling one is how a `st_size` ends up four bytes from where
//! a runtime reads it, and the runtime reports a corrupt filesystem rather
//! than a wrong offset.

/// Linux `open`/`openat` flags, octal as their header writes them.
pub mod open {
    /// Read only — the value is zero, so it is an *absence*, not a bit.
    pub const RDONLY: u64 = 0o0;
    /// Write only.
    pub const WRONLY: u64 = 0o1;
    /// Read and write.
    pub const RDWR: u64 = 0o2;
    /// The low two bits, which carry the access mode.
    pub const ACCMODE: u64 = 0o3;
    /// Create if absent.
    pub const CREAT: u64 = 0o100;
    /// With `CREAT`, fail if it exists.
    pub const EXCL: u64 = 0o200;
    /// Truncate to zero on open.
    pub const TRUNC: u64 = 0o1000;
    /// Every write goes to the end.
    pub const APPEND: u64 = 0o2000;
    /// Never block.
    pub const NONBLOCK: u64 = 0o4000;
    /// Refuse anything that is not a directory.
    pub const DIRECTORY: u64 = 0o200_000;
    /// Refuse a symbolic link at the final component.
    pub const NOFOLLOW: u64 = 0o400_000;
    /// Close this descriptor on `execve`.
    pub const CLOEXEC: u64 = 0o2_000_000;
    /// Bypass the page cache. Refused: this filesystem's cache is where its
    /// journal decides when a dirty page may go home (RFC 0015), so a flag
    /// that asked to skip it would be answered by ignoring it, and a
    /// database told its writes bypassed a cache they did not is worse off
    /// than one told the flag is unavailable.
    pub const DIRECT: u64 = 0o40_000;
    /// Signal-driven I/O. Refused: there is no `SIGIO` to deliver.
    pub const ASYNC: u64 = 0o20_000;
    /// A descriptor that is only a location, not an open file. Refused: it
    /// exists to be passed to `*at` calls this personality does not offer.
    pub const PATH: u64 = 0o10_000_000;
    /// An unnamed file in a directory. Refused: it needs `linkat` to become
    /// visible, and linking is not in any tier.
    pub const TMPFILE: u64 = 0o20_200_000;
}

/// The `dirfd` value meaning "relative to the working directory".
///
/// Negative, and that is load-bearing: it must never be confused with a real
/// descriptor, and a translator that stored it in a `u64` and compared
/// against `usize` would look it up as descriptor 18446744073709551516.
pub const AT_FDCWD: i32 = -100;

/// `stat.st_mode`'s file-type field and the types this system can produce.
pub mod mode {
    /// The bits `st_mode` uses for the file type.
    pub const IFMT: u32 = 0o170_000;
    /// An ordinary file.
    pub const IFREG: u32 = 0o100_000;
    /// A directory.
    pub const IFDIR: u32 = 0o40_000;
    /// A character device — what the console answers as.
    pub const IFCHR: u32 = 0o20_000;
    /// A socket.
    pub const IFSOCK: u32 = 0o140_000;
}

/// `dirent64.d_type` values.
pub mod dirent_type {
    /// Not known; always a legal answer, and a caller must handle it.
    pub const UNKNOWN: u8 = 0;
    /// A directory.
    pub const DIR: u8 = 4;
    /// An ordinary file.
    pub const REG: u8 = 8;
}

/// Errors this module answers with, as Linux numbers.
pub mod errno {
    /// Bad descriptor.
    pub const EBADF: i64 = -9;
    /// Too many open descriptors in this process.
    pub const EMFILE: i64 = -24;
    /// Invalid argument.
    pub const EINVAL: i64 = -22;
    /// Not a directory.
    pub const ENOTDIR: i64 = -20;
    /// Function not implemented.
    pub const ENOSYS: i64 = -38;
    /// The buffer given is too small for one record.
    pub const EINVAL_SHORT: i64 = -22;
}

/// How many descriptors one hosted process may hold.
///
/// Fixed, because this crate does not allocate. Sixty-four is the number a
/// shell utility and a small server both fit inside, and it is a limit a
/// process meets as `EMFILE` — the answer Linux gives — rather than as a
/// failure it cannot name. Raising it is a constant and a test, not a
/// design change.
pub const MAX_DESCRIPTORS: usize = 64;

/// What a descriptor refers to. The adapter decides what a `handle` means;
/// this only records enough to answer `fstat` and to refuse the calls that
/// do not apply — `getdents64` on a socket, `recvfrom` on a directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The console, in either direction. `isatty` is true of these and of
    /// nothing else here.
    Console,
    /// An ordinary file.
    File,
    /// A directory, opened to be read with `getdents64`.
    Directory,
    /// A socket, of either family and either protocol.
    Socket,
    /// An `epoll` set.
    Epoll,
    /// One end of a pipe — [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md)
    /// step 7. Which end is `readable`/`writable`, and the ring itself lives
    /// in the adapter, named by `handle`.
    Pipe,
    /// A `/proc` file the personality generates — RFC 0033 step 10. There is
    /// nothing behind it: no capability, no service, no file. The `handle`
    /// says *which* file, and its contents are written afresh on every read.
    Proc,
}

/// One open descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    /// The adapter's own name for whatever this refers to.
    pub handle: u64,
    /// What it is.
    pub kind: Kind,
    /// Whether `execve` should close it.
    pub close_on_exec: bool,
    /// The read/write position, for the kinds that have one.
    pub offset: u64,
    /// How many bytes there are, for the kinds that have a size.
    ///
    /// Learned when the file was opened and kept, because `read` has to know
    /// where the end is and asking again would be a round trip per call. Zero
    /// for a console or a socket, which have no size and answer `fstat`
    /// differently.
    pub size: u64,
    /// Whether the holder may read.
    pub readable: bool,
    /// Whether the holder may write.
    pub writable: bool,
}

/// A hosted process's descriptor table.
///
/// **Linux's allocation rule is "the lowest free number", and it is not a
/// detail.** Programs depend on it: a shell closes descriptor 0 and opens a
/// file expecting it to *become* standard input, and `dup2(fd, 0)` is the
/// same trick written down. A table that handed out the next number after
/// the highest ever used would run those programs and silently misdirect
/// their input.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    entries: [Option<Entry>; MAX_DESCRIPTORS],
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// An empty table — not even standard input.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_DESCRIPTORS],
        }
    }

    /// The three descriptors a process is entitled to assume, pointed at the
    /// console.
    ///
    /// Called by the adapter when it starts a process, because a Linux
    /// program does not open standard output — it writes to descriptor 1 and
    /// is entitled to find something there. `handle` names the console.
    pub fn install_standard(&mut self, handle: u64) {
        for (number, (readable, writable)) in [(true, false), (false, true), (false, true)]
            .into_iter()
            .enumerate()
        {
            self.entries[number] = Some(Entry {
                handle,
                kind: Kind::Console,
                close_on_exec: false,
                offset: 0,
                size: 0,
                readable,
                writable,
            });
        }
    }

    /// Installs `entry` at the lowest free descriptor at or above `floor`.
    ///
    /// # Errors
    ///
    /// [`errno::EMFILE`] when the table is full — which is the answer Linux
    /// gives, so a program that handles it handles this.
    pub fn insert(&mut self, entry: Entry, floor: usize) -> Result<i32, i64> {
        let free = self
            .entries
            .iter()
            .enumerate()
            .skip(floor)
            .find(|(_, slot)| slot.is_none())
            .map(|(number, _)| number)
            .ok_or(errno::EMFILE)?;
        self.entries[free] = Some(entry);
        // The cast is sound and stays sound: `MAX_DESCRIPTORS` is checked
        // against `i32::MAX` at compile time below.
        Ok(free as i32)
    }

    /// The entry a descriptor names, or nothing.
    #[must_use]
    pub fn get(&self, descriptor: i32) -> Option<&Entry> {
        usize::try_from(descriptor)
            .ok()
            .and_then(|number| self.entries.get(number))
            .and_then(Option::as_ref)
    }

    /// The entry a descriptor names, to be changed — an offset advanced, a
    /// flag set.
    pub fn get_mut(&mut self, descriptor: i32) -> Option<&mut Entry> {
        usize::try_from(descriptor)
            .ok()
            .and_then(|number| self.entries.get_mut(number))
            .and_then(Option::as_mut)
    }

    /// Closes a descriptor, answering what it referred to so the adapter can
    /// release the authority behind it.
    ///
    /// # Errors
    ///
    /// [`errno::EBADF`] if it was not open. **Closing twice is an error and
    /// not a no-op**, because the second close of a number another thread
    /// has since reused is a bug in the program, and a translator that
    /// answered zero would hide it until the wrong file was shut.
    pub fn close(&mut self, descriptor: i32) -> Result<Entry, i64> {
        let number = usize::try_from(descriptor).map_err(|_| errno::EBADF)?;
        let slot = self.entries.get_mut(number).ok_or(errno::EBADF)?;
        slot.take().ok_or(errno::EBADF)
    }

    /// `dup3(from, to, flags)` — make `to` refer to what `from` does.
    ///
    /// Answers what `to` referred to before, if anything, so the adapter can
    /// release it: `dup3` closes the destination silently, and the authority
    /// behind it has to go somewhere.
    ///
    /// # Errors
    ///
    /// [`errno::EBADF`] for a source that is not open or a destination out
    /// of range; [`errno::EINVAL`] when the two are equal — which is
    /// `dup3`'s one difference from `dup2`, and it is deliberate: `dup2`
    /// returns success and `dup3` refuses, so a program using `dup3` to set
    /// `O_CLOEXEC` on a descriptor is told that is not what this call does.
    pub fn dup3(
        &mut self,
        from: i32,
        to: i32,
        close_on_exec: bool,
    ) -> Result<(i32, Option<Entry>), i64> {
        if from == to {
            return Err(errno::EINVAL);
        }
        let source = *self.get(from).ok_or(errno::EBADF)?;
        let number = usize::try_from(to).map_err(|_| errno::EBADF)?;
        if number >= MAX_DESCRIPTORS {
            return Err(errno::EBADF);
        }
        let displaced = self.entries[number].take();
        self.entries[number] = Some(Entry {
            close_on_exec,
            ..source
        });
        Ok((to, displaced))
    }

    /// Closes every descriptor marked `FD_CLOEXEC`, handing each to
    /// `released`, and answers how many went — [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md).
    ///
    /// **The callback is not a convenience; it is the point.** Each entry
    /// carried a handle the adapter holds a capability behind, and an exec
    /// that dropped the rows without telling anybody would leak one per
    /// closed descriptor for the life of the adapter. Handing them back makes
    /// the release the caller's obligation and makes forgetting it visible in
    /// the type rather than in a boot six weeks later.
    pub fn close_on_exec(&mut self, mut released: impl FnMut(Entry)) -> usize {
        let mut closed = 0;
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| entry.close_on_exec)
                && let Some(entry) = slot.take()
            {
                released(entry);
                closed += 1;
            }
        }
        closed
    }

    /// How many descriptors name `handle`.
    ///
    /// **`dup` is what makes this necessary.** Two descriptors may name one
    /// open file, and whoever holds the capability behind that handle must not
    /// give it back while a second row still points at it. Linux keeps a
    /// reference count inside the file object; this crate has no objects, so
    /// the count is a question asked of the table.
    #[must_use]
    pub fn holders(&self, handle: u64) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.handle == handle)
            .count()
    }

    /// How many descriptors are open. For a test, and for a report line.
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.entries.iter().flatten().count()
    }
}

// The cast in `insert` is sound because of this, and it is a build failure
// rather than a comment: a table larger than `i32::MAX` would hand out a
// descriptor number that is negative to every caller.
const _: () = {
    assert!(MAX_DESCRIPTORS < i32::MAX as usize);
};

/// What an `openat(dirfd, path, flags, mode)` means, once the flags are
/// understood: the access it asks for, and what to do if the file is not
/// there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenPlan {
    /// Whether the caller may read.
    pub readable: bool,
    /// Whether the caller may write.
    pub writable: bool,
    /// Create it if it is absent.
    pub create: bool,
    /// With `create`, refuse if it already exists.
    pub exclusive: bool,
    /// Empty it on open.
    pub truncate: bool,
    /// Every write goes to the end.
    pub append: bool,
    /// The caller demands a directory.
    pub directory: bool,
    /// Close on `execve`.
    pub close_on_exec: bool,
}

/// Reads an `openat` flag word.
///
/// **The refused flags are refused rather than ignored, and each says why in
/// [`open`]'s own documentation.** Linux itself ignores unknown bits, and
/// this does too — a future flag arriving as a set bit must not turn a
/// working `open` into an error. The difference is between a bit nobody has
/// defined and one that is defined and asks for a behaviour this system
/// will not perform: silently dropping the second is how a program comes to
/// believe its writes bypassed a cache, or that its file will disappear.
///
/// # Errors
///
/// [`errno::EINVAL`] for an access mode of 3, or for a flag this system
/// refuses to pretend about.
pub fn plan_openat(flags: u64) -> Result<OpenPlan, i64> {
    let access = flags & open::ACCMODE;
    if access == open::ACCMODE {
        return Err(errno::EINVAL);
    }
    for refused in [open::DIRECT, open::ASYNC, open::PATH] {
        if flags & refused == refused {
            return Err(errno::EINVAL);
        }
    }
    // `O_TMPFILE` includes `O_DIRECTORY`'s bits, so it is tested whole and
    // before the directory flag is read — which is exactly the trap its
    // value is shaped to set, and the reason this is not a plain bit test.
    if flags & open::TMPFILE == open::TMPFILE {
        return Err(errno::EINVAL);
    }
    let writable = access == open::WRONLY || access == open::RDWR;
    Ok(OpenPlan {
        readable: access == open::RDONLY || access == open::RDWR,
        writable,
        create: flags & open::CREAT != 0,
        exclusive: flags & open::EXCL != 0,
        truncate: flags & open::TRUNC != 0,
        append: flags & open::APPEND != 0,
        directory: flags & open::DIRECTORY != 0,
        close_on_exec: flags & open::CLOEXEC != 0,
    })
}

/// The bytes of a `struct stat`, x86-64. Confirmed against this machine's
/// `<sys/stat.h>` rather than recalled.
pub const STAT_BYTES: usize = 144;

/// What this system can honestly say about a file.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatFields {
    /// Inode number. A filesystem that has none should give a stable
    /// per-path number rather than zero: `find` and `du` use it to detect
    /// hard links and loops, and every file sharing inode zero looks like
    /// one enormous link farm.
    pub inode: u64,
    /// Type and permission bits — see [`mode`].
    pub mode: u32,
    /// Link count. One, for a filesystem with no hard links.
    pub links: u64,
    /// Size in bytes.
    pub size: u64,
    /// The block size a caller should prefer for I/O.
    pub block_size: u64,
    /// Seconds since the epoch, used for all three timestamps.
    ///
    /// **One field for three, and it is not laziness.** This system has no
    /// wall clock it can defend (RFC 0019 gives deadlines, not dates), so
    /// three separately-wrong times would imply a precision that does not
    /// exist. One value, and the caller can see they are equal.
    pub time: u64,
}

/// Writes a `struct stat` into `out`.
///
/// # Errors
///
/// [`errno::EINVAL`] if the buffer is not [`STAT_BYTES`] long.
pub fn write_stat(out: &mut [u8], fields: &StatFields) -> Result<(), i64> {
    if out.len() < STAT_BYTES {
        return Err(errno::EINVAL);
    }
    out[..STAT_BYTES].fill(0);
    let mut put64 = |at: usize, value: u64| out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    put64(0, 0); //           st_dev   — one device, and it is not named
    put64(8, fields.inode); // st_ino
    put64(16, fields.links); //st_nlink
    put64(40, 0); //          st_rdev  — nothing here is a device node
    put64(48, fields.size); //st_size
    put64(56, fields.block_size); // st_blksize
    // `st_blocks` counts 512-byte units regardless of `st_blksize`, which is
    // the field's oldest and least guessable rule. `du` reads this one, not
    // `st_size`, so a wrong divisor here is a wrong disk-usage report and
    // nothing else visible.
    put64(64, fields.size.div_ceil(512));
    for stamp in [72, 88, 104] {
        put64(stamp, fields.time); // tv_sec; tv_nsec left zero beside it
    }
    out[24..28].copy_from_slice(&fields.mode.to_le_bytes());
    Ok(())
}

/// A `struct dirent64` header is nineteen bytes, and the name follows it
/// with no padding of its own — the record is padded as a whole to eight.
pub const DIRENT_HEADER_BYTES: usize = 19;

/// How long the record for a name of `name` bytes is, rounded as
/// `getdents64` requires.
///
/// **Records are eight-aligned and the length includes the terminator.** A
/// caller walks the buffer by adding `d_reclen`, so a length that is short
/// by the padding lands the next read in the middle of a name, and the
/// symptom is a directory listing with one entry whose name is the rest of
/// the buffer.
#[must_use]
pub const fn dirent_bytes(name: usize) -> usize {
    (DIRENT_HEADER_BYTES + name + 1).next_multiple_of(8)
}

/// Writes one `getdents64` record into `out`.
///
/// Answers how many bytes it took, so a caller can walk on.
///
/// # Errors
///
/// [`errno::EINVAL_SHORT`] when the buffer cannot hold the whole record —
/// which is what Linux answers for a `getdents64` whose buffer is too small
/// for even one entry, and it is *not* a partial write: half a record is
/// unparseable and a caller cannot tell it from a short directory.
pub fn write_dirent(
    out: &mut [u8],
    inode: u64,
    next_offset: u64,
    kind: u8,
    name: &[u8],
) -> Result<usize, i64> {
    if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
        return Err(errno::EINVAL);
    }
    let bytes = dirent_bytes(name.len());
    if out.len() < bytes {
        return Err(errno::EINVAL_SHORT);
    }
    let record = &mut out[..bytes];
    record.fill(0);
    record[0..8].copy_from_slice(&inode.to_le_bytes());
    record[8..16].copy_from_slice(&next_offset.to_le_bytes());
    let reclen = u16::try_from(bytes).map_err(|_| errno::EINVAL)?;
    record[16..18].copy_from_slice(&reclen.to_le_bytes());
    record[18] = kind;
    record[19..19 + name.len()].copy_from_slice(name);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duplicated_descriptor_is_counted_so_its_capability_is_not_dropped_early() {
        let mut table = Table::new();
        let entry = Entry {
            handle: 99,
            kind: Kind::File,
            close_on_exec: false,
            offset: 0,
            size: 10,
            readable: true,
            writable: false,
        };
        let first = table.insert(entry, 0).expect("room");
        assert_eq!(table.holders(99), 1);
        let (second, displaced) = table.dup3(first, first + 5, false).expect("a free number");
        assert!(displaced.is_none());
        assert_eq!(table.holders(99), 2, "two rows name one open file");
        table.close(first).expect("open");
        assert_eq!(
            table.holders(99),
            1,
            "the capability is still named, and must not be given back"
        );
        table.close(second).expect("open");
        assert_eq!(table.holders(99), 0, "now it may be");
    }

    #[test]
    fn the_lowest_free_descriptor_is_the_one_handed_out() {
        let mut table = Table::new();
        table.install_standard(7);
        let entry = Entry {
            handle: 1,
            kind: Kind::File,
            close_on_exec: false,
            offset: 0,
            size: 0,
            readable: true,
            writable: false,
        };
        assert_eq!(table.insert(entry, 0), Ok(3));
        // The shell's trick: close standard input, open a file, and the file
        // *becomes* standard input. A table that counted upward would give 4
        // here and misdirect the program's input without an error anywhere.
        table.close(0).expect("0 was open");
        assert_eq!(table.insert(entry, 0), Ok(0));
    }

    #[test]
    fn a_full_table_answers_emfile() {
        let mut table = Table::new();
        let entry = Entry {
            handle: 1,
            kind: Kind::File,
            close_on_exec: false,
            offset: 0,
            size: 0,
            readable: true,
            writable: false,
        };
        for _ in 0..MAX_DESCRIPTORS {
            table.insert(entry, 0).expect("room");
        }
        assert_eq!(table.insert(entry, 0), Err(errno::EMFILE));
        assert_eq!(table.open_count(), MAX_DESCRIPTORS);
    }

    #[test]
    fn closing_twice_is_an_error() {
        let mut table = Table::new();
        table.install_standard(7);
        assert!(table.close(1).is_ok());
        assert_eq!(table.close(1), Err(errno::EBADF));
        assert_eq!(table.close(-1), Err(errno::EBADF));
        assert_eq!(table.close(MAX_DESCRIPTORS as i32), Err(errno::EBADF));
    }

    #[test]
    fn dup3_displaces_and_refuses_its_own_source() {
        let mut table = Table::new();
        table.install_standard(7);
        let file = Entry {
            handle: 99,
            kind: Kind::File,
            close_on_exec: false,
            offset: 0,
            size: 0,
            readable: true,
            writable: false,
        };
        let fd = table.insert(file, 0).expect("room");
        let (to, displaced) = table.dup3(fd, 0, true).expect("dup3");
        assert_eq!(to, 0);
        // What was standard input comes back, so the adapter can release it.
        assert_eq!(displaced.map(|entry| entry.kind), Some(Kind::Console));
        assert_eq!(table.get(0).map(|entry| entry.handle), Some(99));
        assert_eq!(table.get(0).map(|entry| entry.close_on_exec), Some(true));
        // `dup2` would answer success here; `dup3` refuses, and the two
        // differing is the whole reason a program picks one.
        assert_eq!(table.dup3(0, 0, false), Err(errno::EINVAL));
        assert_eq!(table.dup3(50, 1, false), Err(errno::EBADF));
    }

    #[test]
    fn open_flags_decode_and_the_refusals_refuse() {
        let plan = plan_openat(open::RDWR | open::CREAT | open::CLOEXEC).expect("legal");
        assert!(plan.readable && plan.writable && plan.create && plan.close_on_exec);
        assert!(!plan.truncate && !plan.append && !plan.directory);

        let read_only = plan_openat(open::RDONLY).expect("legal");
        assert!(read_only.readable && !read_only.writable);

        assert_eq!(plan_openat(open::ACCMODE), Err(errno::EINVAL));
        assert_eq!(plan_openat(open::DIRECT), Err(errno::EINVAL));
        assert_eq!(plan_openat(open::ASYNC), Err(errno::EINVAL));
        assert_eq!(plan_openat(open::PATH), Err(errno::EINVAL));
        assert_eq!(plan_openat(open::TMPFILE), Err(errno::EINVAL));
        // `O_TMPFILE` contains `O_DIRECTORY`'s bits. A plain bit test for
        // the directory flag would accept the first and call it the second,
        // which is why the refusal is tested whole and tested here.
        assert_eq!(open::TMPFILE & open::DIRECTORY, open::DIRECTORY);
        // An undefined bit is ignored, as Linux ignores it.
        assert!(plan_openat(open::RDONLY | 1 << 40).is_ok());
    }

    #[test]
    fn a_stat_lands_where_the_headers_say() {
        let mut bytes = [0xffu8; STAT_BYTES];
        write_stat(
            &mut bytes,
            &StatFields {
                inode: 42,
                mode: mode::IFREG | 0o644,
                links: 1,
                size: 4097,
                block_size: 4096,
                time: 1_700_000_000,
            },
        )
        .expect("room");
        let at64 = |offset: usize| {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight bytes"))
        };
        let at32 = |offset: usize| {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
        };
        assert_eq!(at64(8), 42, "st_ino");
        assert_eq!(at32(24), mode::IFREG | 0o644, "st_mode");
        assert_eq!(at64(48), 4097, "st_size");
        assert_eq!(at64(56), 4096, "st_blksize");
        // 4097 bytes is nine 512-byte units, not eight: `st_blocks` rounds
        // up and is counted in 512s whatever `st_blksize` says.
        assert_eq!(at64(64), 9, "st_blocks");
        assert_eq!(at64(72), 1_700_000_000, "st_atim.tv_sec");
        assert_eq!(at64(88), 1_700_000_000, "st_mtim.tv_sec");
        assert_eq!(at64(104), 1_700_000_000, "st_ctim.tv_sec");
        assert_eq!(at64(80), 0, "st_atim.tv_nsec");
        // Every byte the caller gave is written, so nothing of the caller's
        // own stack is left showing through a field this does not fill.
        assert!(bytes.iter().take(STAT_BYTES).any(|byte| *byte != 0xff));
        assert_eq!(bytes[120..STAT_BYTES], [0u8; 24]);

        let mut short = [0u8; STAT_BYTES - 1];
        assert_eq!(
            write_stat(&mut short, &StatFields::default()),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn dirent_records_are_eight_aligned_and_walkable() {
        // 19 header + 3 name + 1 terminator = 23, padded to 24.
        assert_eq!(dirent_bytes(3), 24);
        assert_eq!(dirent_bytes(4), 24);
        assert_eq!(dirent_bytes(5), 32);

        let mut buffer = [0u8; 64];
        let first = write_dirent(&mut buffer, 1, 1, dirent_type::DIR, b"bin").expect("room");
        assert_eq!(first, 24);
        let second =
            write_dirent(&mut buffer[first..], 2, 2, dirent_type::REG, b"hello").expect("room");
        assert_eq!(second, 32);

        // Walk it the way a caller does: by `d_reclen` alone.
        let reclen = u16::from_le_bytes(buffer[16..18].try_into().expect("two"));
        assert_eq!(usize::from(reclen), first);
        assert_eq!(&buffer[19..22], b"bin");
        assert_eq!(buffer[22], 0, "the name is terminated");
        assert_eq!(buffer[18], dirent_type::DIR);
        let next = usize::from(reclen);
        assert_eq!(&buffer[next + 19..next + 24], b"hello");

        // A buffer too small for one whole record is refused, not filled
        // half way: half a record is unparseable and indistinguishable from
        // a short directory.
        let mut tiny = [0u8; 23];
        assert_eq!(
            write_dirent(&mut tiny, 1, 1, dirent_type::REG, b"bin"),
            Err(errno::EINVAL_SHORT)
        );
        assert!(tiny.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_name_that_would_forge_a_path_is_refused() {
        let mut buffer = [0u8; 64];
        assert_eq!(
            write_dirent(&mut buffer, 1, 1, dirent_type::REG, b"a/b"),
            Err(errno::EINVAL)
        );
        assert_eq!(
            write_dirent(&mut buffer, 1, 1, dirent_type::REG, b"a\0b"),
            Err(errno::EINVAL)
        );
        assert_eq!(
            write_dirent(&mut buffer, 1, 1, dirent_type::REG, b""),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn at_fdcwd_is_negative_and_stays_that_way() {
        // The trap this guards: `AT_FDCWD as u64` is 18446744073709551516,
        // and a table lookup on that number is a very large `EBADF` rather
        // than the working directory.
        const { assert!(AT_FDCWD < 0) };
        assert!(Table::new().get(AT_FDCWD).is_none());
    }
}
