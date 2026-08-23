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
    /// A pipe. Spelled `S_IFIFO` in a libc, and the one of these a hosted
    /// program is most likely to test for: a shell decides whether it is on
    /// a terminal or in a pipeline by this field.
    pub const IFIFO: u32 = 0o10_000;
}

// Every value above was read from this machine's
// `/usr/include/x86_64-linux-gnu/bits/stat.h` rather than recalled — the same
// standard `STAT_BYTES` is held to, and for the same reason: a type bit at
// the wrong value makes `stat` answer confidently and wrongly, and nothing
// in this tree could tell.
const _: () = {
    assert!(mode::IFDIR == 0o040_000 && mode::IFCHR == 0o020_000);
    assert!(mode::IFREG == 0o100_000 && mode::IFSOCK == 0o140_000);
    assert!(mode::IFIFO == 0o010_000 && mode::IFMT == 0o170_000);
};

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
    /// Not a terminal — read from this machine's
    /// `/usr/include/asm-generic/errno-base.h`, not recalled. It is what
    /// `isatty` turns into "no", so a program redirecting its output tests
    /// for exactly this on every run.
    pub const ENOTTY: i64 = -25;
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
    /// What the filesystem calls this file — `fstat`'s `st_ino`.
    ///
    /// **Kept beside the handle rather than derived from it.** The handle is
    /// a capability slot, taken from a small pool and *reused*: two files
    /// opened one after the other routinely land in the same slot, so a
    /// `st_ino` derived from it would report them as the same file. `find`
    /// and `du` act on exactly that equality, and would prune the second.
    /// Zero for the kinds that have no filesystem identity — a pipe, a
    /// socket, the console — which is [`StatFields::inode`]'s own caveat and
    /// is why the kinds that *do* have one must carry it.
    pub inode: u64,
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
                inode: 0,
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

/// A `struct new_utsname`: six fields of sixty-five bytes.
///
/// **Read from this machine's `/usr/include/linux/utsname.h`, not recalled.**
/// `__NEW_UTS_LEN` is 64 and each field is one longer for the terminator, and
/// it is the *kernel's* struct rather than glibc's `struct utsname` — those
/// agree here and need not, and what a syscall writes is the kernel's.
pub const UTSNAME_FIELD: usize = 65;
/// The whole of it.
pub const UTSNAME_BYTES: usize = UTSNAME_FIELD * 6;

/// What `uname` answers, and the one field that is a judgement rather than a
/// fact.
///
/// **`sysname` is `Linux`, and that is not a lie about what this is.** The
/// field tells a program which *system-call ABI* it is running on, and that
/// answer is Linux — it is the whole purpose of this personality, and a
/// program that read anything else would pick a different syscall convention
/// and fail immediately. What the field does not claim is that the kernel is
/// Linux, and the two fields below say so in the place a reader of `uname -a`
/// will actually look.
///
/// **`release` is deliberately not a plausible Linux version.** Programs gate
/// features on it — glibc refuses to start below a minimum, and runtimes pick
/// syscalls by it — so reporting `6.x` would promise a syscall surface this
/// adapter does not have and turn a clean refusal into an `ENOSYS` in a
/// corner. A program that declines to run against `0.0.0` has refused
/// *loudly*, which is the better failure. **The trigger for revisiting is the
/// first program observed to refuse for this reason**, and the number it
/// needs; until then this is a claim this system can defend.
pub fn write_utsname(out: &mut [u8]) -> Result<(), i64> {
    if out.len() < UTSNAME_BYTES {
        return Err(errno::EINVAL);
    }
    out[..UTSNAME_BYTES].fill(0);
    let fields = [
        // The ABI, which is the question being asked.
        "Linux",
        "bhaskix",
        // Not a Linux version, on purpose. See above.
        "0.0.0-bhaskix",
        "Bhaskix, a capability system; Linux is the ABI and not the kernel",
        "x86_64",
        // No NIS domain, which Linux itself reports as this exact string
        // rather than as empty.
        "(none)",
    ];
    for (index, field) in fields.iter().enumerate() {
        let at = index * UTSNAME_FIELD;
        let bytes = field.as_bytes();
        // Every field is truncated to leave a terminator, because a caller
        // reads these with `strlen` and an unterminated one runs into the next.
        let take = bytes.len().min(UTSNAME_FIELD - 1);
        out[at..at + take].copy_from_slice(&bytes[..take]);
    }
    Ok(())
}

/// `fcntl` commands this adapter answers.
pub mod fcntl {
    /// Duplicate to the lowest descriptor at or above the argument.
    pub const DUPFD: u64 = 0;
    /// Read the close-on-exec flag.
    pub const GETFD: u64 = 1;
    /// Write it.
    pub const SETFD: u64 = 2;
    /// Read the access mode and status flags.
    pub const GETFL: u64 = 3;
    /// Write the status flags.
    pub const SETFL: u64 = 4;
    /// As [`DUPFD`], with close-on-exec set on the new one.
    pub const DUPFD_CLOEXEC: u64 = 1030;
    /// The only descriptor flag there is.
    pub const FD_CLOEXEC: u64 = 1;
}

/// What an `fcntl` asks this adapter to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fcntl {
    /// Duplicate into the lowest free descriptor at or above `floor`.
    Duplicate {
        /// The lowest number the new descriptor may take.
        floor: i32,
        /// Whether `execve` should close the new one.
        close_on_exec: bool,
    },
    /// Answer the close-on-exec flag.
    ReadDescriptorFlags,
    /// Set it from the argument.
    WriteDescriptorFlags {
        /// What the caller asked for.
        close_on_exec: bool,
    },
    /// Answer the access mode and status flags.
    ReadStatusFlags,
    /// Accept a change to the status flags that changes nothing.
    WriteStatusFlags,
}

/// Reads an `fcntl` command.
///
/// **`F_SETFL` is accepted and does nothing, which is a decision.** The flags
/// it can change are `O_APPEND`, `O_NONBLOCK` and `O_ASYNC`; this adapter has
/// no non-blocking descriptors and no signal-driven I/O, and a file opened
/// read-only cannot append. Refusing would stop programs that set `O_NONBLOCK`
/// defensively on descriptors they then use blockingly — which is most of
/// them. Accepting it *and reporting the flag back* would be the lie; the
/// status flags this answers come from what the descriptor actually is.
///
/// # Errors
///
/// [`errno::EINVAL`] for a command this adapter does not implement, which is
/// every locking command among others. Not [`errno::ENOSYS`]: the call exists.
pub fn plan_fcntl(command: u64, argument: u64) -> Result<Fcntl, i64> {
    match command {
        fcntl::DUPFD | fcntl::DUPFD_CLOEXEC => {
            let floor = i32::try_from(argument).map_err(|_| errno::EINVAL)?;
            if floor < 0 {
                return Err(errno::EINVAL);
            }
            Ok(Fcntl::Duplicate {
                floor,
                close_on_exec: command == fcntl::DUPFD_CLOEXEC,
            })
        }
        fcntl::GETFD => Ok(Fcntl::ReadDescriptorFlags),
        fcntl::SETFD => Ok(Fcntl::WriteDescriptorFlags {
            close_on_exec: argument & fcntl::FD_CLOEXEC != 0,
        }),
        fcntl::GETFL => Ok(Fcntl::ReadStatusFlags),
        fcntl::SETFL => Ok(Fcntl::WriteStatusFlags),
        _ => Err(errno::EINVAL),
    }
}

/// The `ioctl` requests this adapter answers, and it is an allow-list.
///
/// [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) Tier 1 says
/// exactly that — "a small allow-list, not the general mechanism" — and the
/// reason is that `ioctl` is not an interface, it is a namespace of driver
/// interfaces. Answering an unknown request would mean writing to a caller's
/// buffer at a length only the request number implies.
pub mod ioctl {
    /// Read terminal attributes. What `isatty` actually calls.
    pub const TCGETS: u64 = 0x5401;
    /// Read the window size.
    pub const TIOCGWINSZ: u64 = 0x5413;
}

/// What an `ioctl` asks for, if this adapter answers it at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ioctl {
    /// `isatty`: succeed for a console and refuse for everything else.
    AskIfTerminal,
    /// The window size, which this adapter answers as zeroes.
    WindowSize,
}

/// Reads an `ioctl` request against what the descriptor is.
///
/// **`ENOTTY` and not `EINVAL` for a non-console**, because that is the errno
/// `isatty` turns into "no", and a program redirecting its output tests it on
/// every run. A different refusal would make every such program think its
/// pipe was a terminal or its terminal broken.
///
/// # Errors
///
/// [`errno::ENOTTY`] for a request this adapter does not answer, or a terminal
/// request on something that is not one.
pub fn plan_ioctl(request: u64, kind: Kind) -> Result<Ioctl, i64> {
    let terminal = kind == Kind::Console;
    match request {
        ioctl::TCGETS if terminal => Ok(Ioctl::AskIfTerminal),
        ioctl::TIOCGWINSZ if terminal => Ok(Ioctl::WindowSize),
        _ => Err(errno::ENOTTY),
    }
}

/// `lseek`'s `whence`.
pub mod whence {
    /// From the beginning.
    pub const SET: u64 = 0;
    /// From where the descriptor is now.
    pub const CUR: u64 = 1;
    /// From the end of the file.
    pub const END: u64 = 2;
    /// The next hole at or after the offset.
    pub const DATA: u64 = 3;
    /// The next hole — sparse files, which this system does not have.
    pub const HOLE: u64 = 4;
}

/// Where an `lseek` lands.
///
/// **A seek past the end is legal and is not an error**, which is the rule
/// that surprises people: Linux lets a descriptor sit beyond the last byte,
/// and a `read` there returns zero rather than failing. A version that
/// clamped to the size would silently turn a sparse-write pattern into an
/// overwrite of the tail, so the offset is *not* bounded by the size here —
/// only by arithmetic.
///
/// `SEEK_DATA` and `SEEK_HOLE` are refused rather than answered as `SET`.
/// They are questions about which parts of a file are allocated; a
/// filesystem with no holes could answer them truthfully, but this one
/// cannot yet say so with anything it has measured, and a wrong answer to
/// `SEEK_HOLE` is a program that copies a file and drops its tail.
///
/// # Errors
///
/// [`errno::EINVAL`] for an unknown or unsupported `whence`, for a result
/// before the start of the file, or for one that does not fit an `i64` —
/// which is what Linux answers, and is `EOVERFLOW` only for `lseek64` on a
/// 32-bit offset this system does not have.
pub fn plan_lseek(current: u64, size: u64, offset: i64, from: u64) -> Result<u64, i64> {
    let base = match from {
        whence::SET => 0,
        whence::CUR => current,
        whence::END => size,
        _ => return Err(errno::EINVAL),
    };
    // Signed arithmetic throughout, and checked: `base` can be any offset a
    // descriptor has reached and `offset` is the program's own number, so
    // both directions overflow and a wrapped result would be a seek to
    // somewhere nobody asked for.
    let base = i64::try_from(base).map_err(|_| errno::EINVAL)?;
    let landed = base.checked_add(offset).ok_or(errno::EINVAL)?;
    // **This also catches every overflow, and that is not a coincidence.**
    // `base` is non-negative and `offset` is at most `i64::MAX`, so a sum
    // that does not fit can only land negative — there is no input that
    // wraps to a plausible positive offset. So `checked_add` above is
    // belt-and-braces rather than the guard, and no test can tell it from
    // `wrapping_add`; it is kept because a plain `+` here would panic a
    // debug build. Deleting *this* check because it looks like it is only
    // about negative arguments would be the real hole.
    if landed < 0 {
        return Err(errno::EINVAL);
    }
    Ok(landed as u64)
}

/// What `fstat` should answer about `entry`.
///
/// The mode's type bits come from the kind, and the permission bits are
/// **`0o444` or `0o644` and nothing finer**, because this system has no
/// per-file permissions to report and inventing three octal digits per file
/// would be a claim it cannot keep. A caller that tests for writability gets
/// the answer the descriptor actually has.
#[must_use]
pub fn stat_of(entry: &Entry) -> StatFields {
    let kind_bits = match entry.kind {
        Kind::File | Kind::Proc => mode::IFREG,
        Kind::Directory => mode::IFDIR,
        Kind::Console => mode::IFCHR,
        Kind::Socket => mode::IFSOCK,
        // A pipe is `S_IFIFO`, and an `epoll` set is a file in every libc
        // that has looked: neither is a kind this table names elsewhere, so
        // both are written here rather than left to fall through to a
        // regular file, which is what a program calls `fstat` to find out.
        Kind::Pipe => mode::IFIFO,
        Kind::Epoll => mode::IFREG,
    };
    let permissions = if entry.writable { 0o644 } else { 0o444 };
    StatFields {
        inode: entry.inode,
        mode: kind_bits | permissions,
        links: 1,
        size: entry.size,
        // The filesystem's block, which is also what `MAP` lends a page of.
        block_size: 4096,
        time: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_answers_the_abi_in_sysname_and_says_what_it_is_elsewhere() {
        let mut out = [0xffu8; UTSNAME_BYTES];
        write_utsname(&mut out).expect("room");
        let field = |index: usize| {
            let at = index * UTSNAME_FIELD;
            let bytes = &out[at..at + UTSNAME_FIELD];
            let end = bytes.iter().position(|byte| *byte == 0).expect("terminated");
            core::str::from_utf8(&bytes[..end]).expect("ascii").to_string()
        };
        // The ABI, which is the question `sysname` asks and the one field a
        // program branches on.
        assert_eq!(field(0), "Linux");
        assert_eq!(field(4), "x86_64");
        // And the fields where a reader of `uname -a` finds out what this
        // really is. If the system's own name stops appearing here, the
        // `sysname` above has become a plain lie.
        assert!(field(3).contains("Bhaskix"), "version: {}", field(3));
        assert!(field(2).contains("bhaskix"), "release: {}", field(2));
        // **Not a plausible Linux version**, deliberately: a program that
        // gates on it should refuse loudly rather than proceed into ENOSYS.
        assert!(field(2).starts_with("0."), "release: {}", field(2));
    }

    #[test]
    fn every_uname_field_is_terminated_even_when_it_is_too_long_to_fit() {
        let mut out = [0xffu8; UTSNAME_BYTES];
        write_utsname(&mut out).expect("room");
        for index in 0..6 {
            let at = index * UTSNAME_FIELD;
            assert_eq!(
                out[at + UTSNAME_FIELD - 1],
                0,
                "field {index} runs into the next, and a caller reads these with strlen"
            );
        }
    }

    #[test]
    fn a_short_uname_buffer_is_refused_rather_than_partly_filled() {
        let mut out = [0u8; UTSNAME_BYTES - 1];
        assert_eq!(write_utsname(&mut out), Err(errno::EINVAL));
    }

    #[test]
    fn fcntl_reads_the_two_duplicating_commands_and_their_difference() {
        assert_eq!(
            plan_fcntl(fcntl::DUPFD, 7),
            Ok(Fcntl::Duplicate {
                floor: 7,
                close_on_exec: false
            })
        );
        assert_eq!(
            plan_fcntl(fcntl::DUPFD_CLOEXEC, 7),
            Ok(Fcntl::Duplicate {
                floor: 7,
                close_on_exec: true
            })
        );
    }

    #[test]
    fn fcntl_sets_close_on_exec_from_the_flag_and_not_from_the_word() {
        // `FD_CLOEXEC` is bit zero and the ABI header says "anything with the
        // low bit set goes". A version that compared the whole word would
        // leave the flag clear for every caller that passed a wider one.
        assert_eq!(
            plan_fcntl(fcntl::SETFD, 1),
            Ok(Fcntl::WriteDescriptorFlags {
                close_on_exec: true
            })
        );
        assert_eq!(
            plan_fcntl(fcntl::SETFD, 0),
            Ok(Fcntl::WriteDescriptorFlags {
                close_on_exec: false
            })
        );
        assert_eq!(
            plan_fcntl(fcntl::SETFD, 3),
            Ok(Fcntl::WriteDescriptorFlags {
                close_on_exec: true
            }),
            "the low bit is what counts"
        );
        assert_eq!(
            plan_fcntl(fcntl::SETFD, 2),
            Ok(Fcntl::WriteDescriptorFlags {
                close_on_exec: false
            }),
            "and a word without it is not close-on-exec"
        );
    }

    #[test]
    fn an_fcntl_this_adapter_does_not_implement_is_refused_and_not_ignored() {
        // The locking commands, among others. Answering `Ok` would tell a
        // program its lock was taken.
        for command in [5u64, 6, 7, 8, 1024, u64::MAX] {
            assert_eq!(plan_fcntl(command, 0), Err(errno::EINVAL), "{command}");
        }
    }

    #[test]
    fn ioctl_answers_a_terminal_only_for_a_console() {
        assert_eq!(
            plan_ioctl(ioctl::TCGETS, Kind::Console),
            Ok(Ioctl::AskIfTerminal)
        );
        // **ENOTTY and nothing else**: it is what `isatty` turns into "no",
        // and every program that redirects its output asks this.
        for kind in [Kind::File, Kind::Pipe, Kind::Socket, Kind::Directory] {
            assert_eq!(
                plan_ioctl(ioctl::TCGETS, kind),
                Err(errno::ENOTTY),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_ioctl_outside_the_allow_list_is_refused_even_on_a_console() {
        // The point of an allow-list: an unknown request would mean writing
        // to a caller's buffer at a length only the number implies.
        for request in [0u64, 0x5402, 0x5414, 0x8912, u64::MAX] {
            assert_eq!(
                plan_ioctl(request, Kind::Console),
                Err(errno::ENOTTY),
                "{request:#x}"
            );
        }
    }

    #[test]
    fn a_seek_past_the_end_is_where_the_descriptor_goes_rather_than_an_error() {
        // Linux allows it and programs rely on it: this is how a file is
        // extended by seeking and writing. Clamping to the size here would
        // turn that into an overwrite of the last byte.
        assert_eq!(plan_lseek(0, 10, 4096, whence::SET), Ok(4096));
        assert_eq!(plan_lseek(10, 10, 90, whence::END), Ok(100));
    }

    #[test]
    fn a_seek_before_the_start_is_refused_from_every_whence() {
        assert_eq!(plan_lseek(0, 10, -1, whence::SET), Err(errno::EINVAL));
        assert_eq!(plan_lseek(4, 10, -5, whence::CUR), Err(errno::EINVAL));
        assert_eq!(plan_lseek(0, 10, -11, whence::END), Err(errno::EINVAL));
        // And landing exactly on zero is not before the start.
        assert_eq!(plan_lseek(4, 10, -4, whence::CUR), Ok(0));
        assert_eq!(plan_lseek(0, 10, -10, whence::END), Ok(0));
    }

    #[test]
    fn seek_from_the_end_measures_from_the_size_and_from_current_the_offset() {
        // The two are only the same when the descriptor is at the end, which
        // is the case a test that used one number for both would pass on.
        assert_eq!(plan_lseek(3, 10, 0, whence::END), Ok(10));
        assert_eq!(plan_lseek(3, 10, 0, whence::CUR), Ok(3));
    }

    #[test]
    fn seek_data_and_seek_hole_are_refused_rather_than_answered_as_set() {
        // A file system with no holes could answer these, and this one has
        // not measured that it has none. Answering `SET` would put the
        // descriptor at the caller's offset and report it as the start of
        // data, which is a copy that silently drops a tail.
        assert_eq!(plan_lseek(0, 10, 0, whence::DATA), Err(errno::EINVAL));
        assert_eq!(plan_lseek(0, 10, 0, whence::HOLE), Err(errno::EINVAL));
        assert_eq!(plan_lseek(0, 10, 0, 5), Err(errno::EINVAL));
        assert_eq!(plan_lseek(0, 10, 0, u64::MAX), Err(errno::EINVAL));
    }

    #[test]
    fn a_seek_that_would_overflow_is_refused_rather_than_wrapping_to_a_small_offset() {
        // **What carries this is the sign check and the `i64` conversion, not
        // `checked_add`** -- swapping that for `wrapping_add` leaves every
        // case here still refused, because an overflow from a non-negative
        // base can only land negative. Said here because a reader who saw
        // `checked_add` and this test would reasonably assume the one tests
        // the other, and would delete the sign check first.
        assert_eq!(plan_lseek(u64::MAX, 0, 1, whence::CUR), Err(errno::EINVAL));
        assert_eq!(
            plan_lseek(i64::MAX as u64, 0, 1, whence::CUR),
            Err(errno::EINVAL)
        );
        assert_eq!(plan_lseek(0, u64::MAX, 0, whence::END), Err(errno::EINVAL));
        assert_eq!(
            plan_lseek(i64::MAX as u64, 0, i64::MAX, whence::CUR),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn stat_tells_a_directory_from_a_file_and_neither_from_a_console() {
        let of = |kind| {
            stat_of(&Entry {
                handle: 1,
                inode: 9,
                kind,
                close_on_exec: false,
                offset: 0,
                size: 40,
                readable: true,
                writable: false,
            })
            .mode
                & mode::IFMT
        };
        assert_eq!(of(Kind::File), mode::IFREG);
        assert_eq!(of(Kind::Directory), mode::IFDIR);
        assert_eq!(of(Kind::Console), mode::IFCHR);
        assert_eq!(of(Kind::Socket), mode::IFSOCK);
        // A pipe is not a regular file, and a program that stats one to
        // decide whether it may seek reads exactly this field.
        assert_eq!(of(Kind::Pipe), mode::IFIFO);
    }

    #[test]
    fn stat_answers_the_inode_the_entry_carries_and_never_its_handle() {
        // The trap this field exists for: the handle is a slot number, taken
        // from a pool of thirty-two and reused, so two files opened one after
        // another share one. `find` prunes what it thinks it has visited.
        let entry = Entry {
            handle: 127,
            inode: 3,
            kind: Kind::File,
            close_on_exec: false,
            offset: 0,
            size: 40,
            readable: true,
            writable: false,
        };
        assert_eq!(stat_of(&entry).inode, 3);
        assert_ne!(stat_of(&entry).inode, entry.handle);
    }

    #[test]
    fn a_written_stat_carries_the_size_and_mode_at_the_offsets_the_struct_puts_them() {
        // Raw offsets, not a round trip through this module's own reader --
        // there is no reader, and the caller is a libc that knows only the
        // layout. A field written to the wrong offset round-trips perfectly
        // and is still wrong.
        let mut out = [0u8; STAT_BYTES];
        write_stat(
            &mut out,
            &stat_of(&Entry {
                handle: 1,
                inode: 0x1122,
                kind: Kind::Directory,
                close_on_exec: false,
                offset: 0,
                size: 0x3344,
                readable: true,
                writable: false,
            }),
        )
        .expect("room");
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 0x1122);
        assert_eq!(
            u32::from_le_bytes(out[24..28].try_into().unwrap()),
            mode::IFDIR | 0o444
        );
        assert_eq!(u64::from_le_bytes(out[48..56].try_into().unwrap()), 0x3344);
    }

    #[test]
    fn a_duplicated_descriptor_is_counted_so_its_capability_is_not_dropped_early() {
        let mut table = Table::new();
        let entry = Entry {
            handle: 99,
            inode: 0,
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
            inode: 0,
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
            inode: 0,
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
            inode: 0,
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
