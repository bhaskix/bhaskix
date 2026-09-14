// SPDX-License-Identifier: Apache-2.0
//! A Linux program, loaded off the filesystem by a hosted `execve`.
//!
//! [RFC 0059](../../docs/rfc/0059-an-execve-that-runs-a-program.md) step 6.
//! Everything this program does is a Linux system call answered by
//! `bin/linuxd`, and everything it prints is something no other part of the
//! machine could have invented:
//!
//! * **its arguments and environment**, which its parent chose and which had
//!   to survive being read out of one address space and written into another;
//! * **its pid**, which the adapter keeps across the exec and which the boot
//!   test checks against the adapter's own record of the same number;
//! * **whether the auxiliary vector is real**, which is the part most likely
//!   to be silently wrong — an `AT_RANDOM` pointing at nothing, or an
//!   `AT_PAGESZ` of zero, produce a program that runs and misbehaves rather
//!   than one that fails.
//!
//! It is deliberately not a shell, a libc, or anything with a runtime: what is
//! under test is the loader, and a program with a runtime would be testing the
//! runtime's opinion of the loader instead.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Linux system call numbers, `x86_64`.
mod nr {
    /// `write(fd, buffer, count)`.
    pub const WRITE: u64 = 1;
    /// `getpid()`.
    pub const GETPID: u64 = 39;
    /// `exit_group(status)`.
    pub const EXIT_GROUP: u64 = 231;
    /// `open(path, flags, mode)`.
    pub const OPEN: u64 = 2;
    /// `close(fd)`.
    pub const CLOSE: u64 = 3;
    /// `read(fd, buffer, count)`.
    pub const READ: u64 = 0;
    /// `mkdir(path, mode)`.
    pub const MKDIR: u64 = 83;
    /// `unlink(path)`.
    pub const UNLINK: u64 = 87;
    /// `ftruncate(fd, length)`.
    pub const FTRUNCATE: u64 = 46;
    /// `execve(path, argv, envp)`.
    pub const EXECVE: u64 = 59;
}

/// `open` flags, from this machine's own headers.
mod open {
    /// Read only.
    pub const RDONLY: u64 = 0o0;
    /// Write only.
    pub const WRONLY: u64 = 0o1;
    /// Create if absent.
    ///
    /// **Used since RFC 0060 step 3.** This constant carried a note saying it
    /// was deliberately unused, because opening with it reddened the TCP
    /// inbound gate 5 boots of 5 on 2026-08-31 and which half of the system
    /// was at fault had never been established. Re-measured on 2026-09-13
    /// against a tree thirteen days newer: 0 red of 10, with the journal
    /// commit demonstrably happening on every one. The note is retired and
    /// the measurement that retired it is in TRACKER §3.
    pub const CREAT: u64 = 0o100;
    /// Truncate to nothing on open, which is what `>` means.
    pub const TRUNC: u64 = 0o1000;
}

/// Auxiliary-vector entry types this program checks.
mod auxv {
    /// End of vector.
    pub const NULL: u64 = 0;
    /// Page size in bytes.
    pub const PAGESZ: u64 = 6;
    /// Address of the program headers in this process's own space.
    pub const PHDR: u64 = 3;
    /// Size of one program-header entry.
    pub const PHENT: u64 = 4;
    /// How many program-header entries there are.
    pub const PHNUM: u64 = 5;
    /// The program's entry point.
    pub const ENTRY: u64 = 9;
    /// Sixteen bytes of startup entropy.
    pub const RANDOM: u64 = 25;
}

/// There is nothing to unwind and nothing that could print.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A program that panicked
    // has nothing correct left to do, and stopping is visible to the kernel
    // where carrying on would not be.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// One Linux system call.
fn syscall(number: u64, one: u64, two: u64, three: u64) -> u64 {
    let result: u64;
    // SAFETY: the Linux `x86_64` convention — number in `rax`, arguments in
    // `rdi`, `rsi`, `rdx`, result in `rax`, and `rcx` and `r11` clobbered by
    // the instruction itself. Nothing here is dereferenced by this program;
    // the pointers it passes are its own and the adapter reads them through a
    // capability rather than through this address space.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") one,
            in("rsi") two,
            in("rdx") three,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Writes to standard output, and does not care whether it all went: this
/// program's whole output is one line and a short write would show as a
/// truncated line, which is a failure the boot test can see.
fn write(bytes: &[u8]) {
    let _ = syscall(nr::WRITE, 1, bytes.as_ptr() as u64, bytes.len() as u64);
}

/// A line assembled in one buffer, so it reaches the console as one write.
///
/// **Not several writes.** The console is shared with every other domain on
/// the machine, and a line built out of six writes is a line another domain
/// can print into the middle of — which is a flake in the boot test that has
/// nothing to do with what is being tested.
struct Line {
    bytes: [u8; 512],
    used: usize,
}

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            used: 0,
        }
    }

    /// Appends what fits. A line that overflows is truncated rather than
    /// wrapped, and the boot test's exact match is what notices.
    fn put(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if self.used == self.bytes.len() {
                return;
            }
            self.bytes[self.used] = *byte;
            self.used += 1;
        }
    }

    /// Appends a decimal number.
    fn number(&mut self, mut value: u64) {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 || at == 0 {
                break;
            }
        }
        self.put(&digits[at..]);
    }

    fn flush(&self) {
        write(&self.bytes[..self.used]);
    }
}

/// Reads the `u64` at `at`, which is inside the initial process image.
///
/// # Safety
///
/// `at` must be an eight-byte-aligned address inside the image the program was
/// entered on, or inside a string that image points at.
unsafe fn word(at: *const u64) -> u64 {
    // SAFETY: the caller's obligation, and every call site below walks the
    // image from `rsp` outwards using the counts the image itself carries —
    // which is what `_start` is given and what System V says is there.
    unsafe { core::ptr::read(at) }
}

/// The length of a NUL-terminated string, bounded so a missing NUL cannot run
/// this program off the end of its own address space.
///
/// # Safety
///
/// `at` must point at readable bytes.
unsafe fn length_of(at: *const u8) -> usize {
    let mut length = 0usize;
    while length < 256 {
        // SAFETY: the caller's obligation; bounded by the loop.
        if unsafe { core::ptr::read(at.add(length)) } == 0 {
            break;
        }
        length += 1;
    }
    length
}

/// Appends the string at `at`.
///
/// # Safety
///
/// As [`length_of`].
unsafe fn put_string(line: &mut Line, at: u64) {
    let pointer = at as *const u8;
    // SAFETY: the caller's obligation.
    let length = unsafe { length_of(pointer) };
    // SAFETY: `length` bytes were just found readable, ending before a NUL.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
    line.put(bytes);
}

/// The program, entered on the initial process image `_start` found at `rsp`.
///
/// `stack` points at `argc`, which is what System V says `rsp` holds at entry
/// and what `bhaskix_personality::stack::Builder` lays out.
#[unsafe(no_mangle)]
extern "C" fn hosted_main(stack: *const u64) -> ! {
    let mut line = Line::new();
    line.put(b"hosted pid ");
    line.number(syscall(nr::GETPID, 0, 0, 0));

    // SAFETY: `stack` is the initial process image this program was entered
    // on. Every read below walks it using its own counts and terminators, in
    // the order System V defines: `argc`, then `argc` pointers, then a NULL,
    // then the environment to its NULL, then the auxiliary vector to
    // `AT_NULL`. A malformed image is exactly what this program exists to
    // detect, and the bounds that keep it from running away are the counts it
    // reads and `length_of`'s cap.
    let argc = unsafe { word(stack) };
    let mut at = 1usize;

    line.put(b" args");
    for _ in 0..argc.min(16) {
        // SAFETY: inside `argc` pointers that follow `argc` itself.
        let pointer = unsafe { word(stack.add(at)) };
        at += 1;
        if pointer == 0 {
            break;
        }
        line.put(b" ");
        // SAFETY: a pointer the image gave, into its own strings block.
        unsafe { put_string(&mut line, pointer) };
    }
    // Step over whatever is left of `argv` and its terminating NULL.
    // SAFETY: as above; the image is NULL-terminated by construction.
    while unsafe { word(stack.add(at)) } != 0 {
        at += 1;
    }
    at += 1;

    line.put(b" env");
    loop {
        // SAFETY: inside the environment vector, which ends at a NULL.
        let pointer = unsafe { word(stack.add(at)) };
        at += 1;
        if pointer == 0 {
            break;
        }
        line.put(b" ");
        // SAFETY: a pointer the image gave, into its own strings block.
        unsafe { put_string(&mut line, pointer) };
    }

    // The auxiliary vector, which is where a wrong image hides. Reported as
    // one word, because what matters to the gate is whether it is *all* right.
    let mut pagesz = 0u64;
    let mut entry = 0u64;
    let mut random = 0u64;
    let mut phdr = 0u64;
    let mut phent = 0u64;
    let mut phnum = 0u64;
    loop {
        // SAFETY: inside the auxiliary vector, which ends at an `AT_NULL`
        // pair.
        let kind = unsafe { word(stack.add(at)) };
        // SAFETY: every auxv entry is a pair, so the value follows the type.
        let value = unsafe { word(stack.add(at + 1)) };
        at += 2;
        match kind {
            auxv::PAGESZ => pagesz = value,
            auxv::ENTRY => entry = value,
            auxv::RANDOM => random = value,
            auxv::PHDR => phdr = value,
            auxv::PHENT => phent = value,
            auxv::PHNUM => phnum = value,
            auxv::NULL => break,
            _ => {}
        }
    }
    // `AT_RANDOM` must point at sixteen bytes that are actually there and are
    // not all zero — a runtime seeds its hashing from them, and a pointer to a
    // page of zeroes is the failure that looks like success.
    let entropy = if random == 0 {
        0
    } else {
        // SAFETY: `AT_RANDOM` names sixteen bytes inside the initial image,
        // which is mapped read-write and was written by the loader.
        unsafe { word(random as *const u64) }
    };
    // **`AT_PHDR` is followed rather than merely counted.** A non-zero pointer
    // proves nothing; what a runtime does with it is walk the table, so this
    // walks the first entry and requires it to be a `PT_LOAD` — which is what
    // the first program header of this program is, and which a pointer at the
    // wrong address will not be. It is the one auxv field that can be wrong by
    // an amount too small to crash anything.
    let headers_found = phent == 56 && phnum >= 1 && phdr != 0 && {
        // SAFETY: `AT_PHDR` names the program header table in this process's
        // own space. This program's first segment maps the ELF header and that
        // table, so if the loader computed the address correctly the bytes are
        // mapped read-only and readable here. `p_type` is the first four bytes
        // of an ELF64 program header.
        let kind = unsafe { core::ptr::read(phdr as *const u32) };
        kind == 1 // PT_LOAD
    };
    line.put(
        if pagesz == 4096 && entry != 0 && entropy != 0 && headers_found {
            b" auxv ok".as_slice()
        } else {
            b" auxv BAD".as_slice()
        },
    );

    line.put(b"\n");
    line.flush();

    // RFC 0060: create a file, write to it, read it back, and refuse to write
    // where nothing may be written.
    write_and_read_back();

    // **RFC 0068's demonstration: run a command through somebody else's
    // shell.** Everything below this line was built for it -- RFC 0059 made
    // `execve` resolve a real path, RFC 0064 took away the loader's window,
    // RFC 0065 took away the ten-block file, RFC 0069 made the filesystem the
    // disk's size, and RFC 0068's flag put 2,172,376 bytes of BusyBox on it.
    //
    // Harmless where BusyBox is not staged, which is every lane by default:
    // `execve` answers `ENOENT`, this returns, and the program exits as it
    // always did. A gate that asserted the output unconditionally would fail
    // four lanes for a file they were never given.
    exec_busybox();

    syscall(nr::EXIT_GROUP, 0, 0, 0);
    // `exit_group` does not return. If it somehow does, stopping here is the
    // only honest thing left.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Replaces this program with BusyBox, running one command.
///
/// Returns only if the `execve` failed, which on a machine without BusyBox
/// staged is what happens and is not an error: `/busybox` is put on the disk
/// only when the kernel is asked for it.
///
/// The argument vector is the interesting part. `busybox sh -c '/busybox echo
/// <text>'` proves three things in one line: BusyBox dispatches on `argv[1]` to
/// its **shell**, so the vector this kernel built is the one a foreign program
/// expected to read; that shell **parses** `argv[3]`, so what was reached is a
/// shell and not an applet; and the command it finds is a **path** rather than
/// a builtin, so the shell `fork`s, `execve`s a child and waits for it.
///
/// The text is printed by a process the shell created. An earlier version ran
/// `echo` as a builtin, which proved the first two.
fn exec_busybox() {
    const PATH: &[u8] = b"/busybox\0";
    const ARG0: &[u8] = b"busybox\0";
    const ARG1: &[u8] = b"sh\0";
    const ARG2: &[u8] = b"-c\0";
    const ARG3: &[u8] = b"/busybox echo bhaskix-busybox-forked\0";

    let argv = [
        ARG0.as_ptr() as u64,
        ARG1.as_ptr() as u64,
        ARG2.as_ptr() as u64,
        ARG3.as_ptr() as u64,
        0,
    ];
    let envp = [0u64];

    let mut line = Line::new();
    line.put(b"hosted exec busybox ");
    let failed = syscall(
        nr::EXECVE,
        PATH.as_ptr() as u64,
        argv.as_ptr() as u64,
        envp.as_ptr() as u64,
    );
    // Reached only on failure: a successful `execve` never returns here,
    // because there is no here to return to.
    line.put(b"refused errno ");
    line.number(failed.wrapping_neg());
    line.put(b"\n");
    line.flush();
}

/// Bytes that exist only to make this program larger than the loader's window.
///
/// **RFC 0064 step 4, unblocked by RFC 0065.** The adapter's staging object is
/// sixteen pages and RFC 0064 made it a window the file streams through; proving
/// that needs a program bigger than the window, and storing one needed the
/// filesystem to stop capping every file at ten blocks. With both, the boot that
/// loads this is loading something neither the old loader nor the old filesystem
/// could handle.
///
/// A non-zero fill on purpose: zeroes would land in `.bss`, cost nothing in the
/// file, and leave the program exactly as small as before. `#[used]` so the
/// linker cannot decide this is unreachable and quietly undo the test.
///
/// **Sized to clear both limits and no further.** 64 KiB of padding makes the
/// program about 77 KB: past the 40,960-byte file limit RFC 0065 removed and
/// past the 65,536-byte loader window RFC 0064 removed, which is everything
/// this has to prove. It was 96 KiB for an afternoon, and every block of it is
/// a journal transaction the kernel runs at boot before anything else starts --
/// the `iommu-off` lane timed out once under the concurrent suite at that size.
/// A fixture large enough to demonstrate a limit is the right size; larger is
/// boot time spent on nothing.
#[used]
#[unsafe(no_mangle)]
static WIDER_THAN_THE_WINDOW: [u8; 64 * 1024] = [0x5a; 64 * 1024];

/// The whole of RFC 0060 from a hosted program's side: create, write, close,
/// reopen, read back — and be refused where nothing may be written.
///
/// **The prefix is `hosted tmp` and not `hosted write`, which is taken.**
/// RFC 0032 step 10's hand-assembled corpus program writes the literal
/// `hosted write ok\n` out of the adapter's console capability, and
/// `boot-test.sh` greps for exactly that. A second producer of the same bytes
/// would let that gate pass on the wrong program's output.
///
/// **The body is what proves it.** The gate matches on these exact bytes, and
/// no other part of this machine emits them: they exist only in this program's
/// `.rodata`, and the only way they can reach the console a second time is by
/// having gone out to a real file on the disk and come back. A gate that
/// asserted "the write returned a positive number" would pass on a write the
/// filesystem discarded.
///
/// **The refusal is the more important half.** A machine where a hosted
/// program can write under `/tmp` is the feature; a machine where it can write
/// anywhere else is a broken containment claim, and RFC 0031 I3 is what would
/// be broken. So the read-only root is attempted on every boot and the errno
/// is printed rather than assumed.
fn write_and_read_back() {
    const PATH: &[u8] = b"/tmp/hosted.txt\0";
    /// A file that **exists** under the read-only root and must never become
    /// writable.
    ///
    /// **The name has to be real, and an earlier draft's was not.** With a
    /// name that is not there, the open is refused for absence and the gate
    /// passes without ever testing writability -- which the arming caught:
    /// removing the adapter's `EROFS` guard left the probe printing `errno 2`
    /// and the gate saying it could not tell. `inner` is created under `sub`
    /// by the kernel on every machine that formats this disk.
    const SEALED: &[u8] = b"/inner\0";
    const BODY: &[u8] = b"a hosted process wrote this through a capability";

    // **The containment arm runs first, because it must not be skippable.**
    // Every failure path below returns early, so with this at the end an
    // unrelated short write would take the containment assertion with it and
    // the gate would report "did not say" for the one claim that matters most.
    // Watched: dropping the write silently made both arms red, and only one of
    // them was about the write.
    //
    // `open` for writing under the read-only root must answer `EROFS`, and
    // must do so without the filesystem service ever being asked -- the
    // adapter holds nothing there that could carry a write.
    let mut sealed = Line::new();
    sealed.put(b"hosted sealed ");
    let refused = syscall(nr::OPEN, SEALED.as_ptr() as u64, open::WRONLY, 0);
    if (refused as i64) < 0 {
        sealed.put(b"refused errno ");
        sealed.number(refused.wrapping_neg());
    } else {
        sealed.put(b"OPENED FOR WRITING, fd ");
        sealed.number(refused);
        syscall(nr::CLOSE, refused, 0, 0);
    }
    sealed.put(b"\n");
    sealed.flush();

    let mut line = Line::new();
    line.put(b"hosted tmp ");

    let fd = syscall(
        nr::OPEN,
        PATH.as_ptr() as u64,
        open::WRONLY | open::CREAT | open::TRUNC,
        0o644,
    );
    if (fd as i64) < 0 {
        line.put(b"open refused errno ");
        line.number(fd.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let wrote = syscall(nr::WRITE, fd, BODY.as_ptr() as u64, BODY.len() as u64);
    syscall(nr::CLOSE, fd, 0, 0);
    if (wrote as i64) != BODY.len() as i64 {
        line.put(b"wrote ");
        line.number(wrote);
        line.put(b" of ");
        line.number(BODY.len() as u64);
        line.put(b"\n");
        line.flush();
        return;
    }

    // **Reopened rather than rewound**, because a descriptor that never left
    // the adapter could be answered out of a record this program's own write
    // just updated. A second `open` resolves the name again and the bytes come
    // off the disk through the filesystem service.
    let back = syscall(nr::OPEN, PATH.as_ptr() as u64, open::RDONLY, 0);
    if (back as i64) < 0 {
        line.put(b"reopen refused errno ");
        line.number(back.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let mut buffer = [0u8; 64];
    let read = syscall(
        nr::READ,
        back,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    syscall(nr::CLOSE, back, 0, 0);
    if (read as i64) != BODY.len() as i64 {
        line.put(b"read back ");
        line.number(read);
        line.put(b" of ");
        line.number(BODY.len() as u64);
        line.put(b"\n");
        line.flush();
        return;
    }
    if &buffer[..BODY.len()] != BODY {
        line.put(b"read back the wrong bytes\n");
        line.flush();
        return;
    }
    line.put(b"ok: ");
    line.put(&buffer[..BODY.len()]);
    line.put(b"\n");
    line.flush();

    truncate_over_a_longer_file();
    truncate_where_it_cannot_be_honoured();
    write_past_one_chunk();
    change_the_directory();
}

/// More than one page in a single `write`, which is what says the adapter
/// loops.
///
/// **The number is the assertion.** `COPY_IN` moves at most one page and
/// `WRITE_FROM` takes at most one page, so 5,000 bytes cannot cross in one
/// round trip. A `write` that answers 5,000 has been through the loop at least
/// twice; one that answers 4,096 has not, which is the short write RFC 0060
/// decided against and which plenty of Linux software mishandles.
fn write_past_one_chunk() {
    const PATH: &[u8] = b"/tmp/bulk\0";

    let mut line = Line::new();
    line.put(b"hosted bulk ");
    let fd = syscall(
        nr::OPEN,
        PATH.as_ptr() as u64,
        open::WRONLY | open::CREAT | open::TRUNC,
        0o644,
    );
    if (fd as i64) < 0 {
        line.put(b"open refused errno ");
        line.number(fd.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let wrote = syscall(nr::WRITE, fd, BULK.as_ptr() as u64, BULK.len() as u64);
    syscall(nr::CLOSE, fd, 0, 0);
    if (wrote as i64) != BULK.len() as i64 {
        line.put(b"wrote ");
        line.number(wrote);
        line.put(b" of ");
        line.number(BULK.len() as u64);
        line.put(b"\n");
        line.flush();
        return;
    }
    // A count is not bytes on a disk. Reading the head back says the first
    // chunk is really there; the count says the second one went too.
    let back = syscall(nr::OPEN, PATH.as_ptr() as u64, open::RDONLY, 0);
    if (back as i64) < 0 {
        line.put(b"reopen refused errno ");
        line.number(back.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let mut head = [0u8; 32];
    let read = syscall(nr::READ, back, head.as_mut_ptr() as u64, head.len() as u64);
    syscall(nr::CLOSE, back, 0, 0);
    if (read as i64) != head.len() as i64 || head.iter().any(|byte| *byte != BULK_BYTE) {
        line.put(b"read back the wrong head\n");
        line.flush();
        return;
    }
    line.put(b"ok: ");
    line.number(wrote);
    line.put(b" bytes in one write, past the one-page chunk\n");
    line.flush();
}

/// The byte [`BULK`] is filled with, checked on the way back out.
const BULK_BYTE: u8 = 0x42;

/// A buffer larger than one page, so a `write` of it cannot be one round trip.
static BULK: [u8; 5000] = [BULK_BYTE; 5000];

/// RFC 0077, second pass: an `O_TRUNC` this system cannot honour is refused.
///
/// **Three places dropped the flag in silence** until 2026-09-14 — a file
/// under the read-only root, this process's own root directory, and a
/// generated `/proc` file. Each answered with a descriptor, which tells the
/// caller the file is now empty when it is not: exactly the wrong RFC 0077
/// was written to fix, one directory over.
///
/// The numbers are Linux's, measured on the build host rather than recalled:
/// `EROFS`, `EISDIR`, `EACCES`.
///
/// **The control arm is the point.** Each path is opened again *without*
/// `O_TRUNC` and must succeed — otherwise this gate would pass just as well
/// on a system that could not open those names at all, which is how a
/// containment check in this same file once passed on a file that did not
/// exist.
fn truncate_where_it_cannot_be_honoured() {
    /// A file in the read-only root, with bytes in it that have to survive.
    ///
    /// The same name the containment arms use, and for the same reason: this
    /// process's root is a capability to `sub/` on the disk, so `inner` is a
    /// file it can actually reach. A name that is not there answers `ENOENT`
    /// before any of this is consulted, and the gate would be measuring a
    /// spelling mistake.
    const SEALED: &[u8] = b"/inner\0";
    /// This process's own root, which is a directory.
    const ROOT: &[u8] = b"/\0";
    /// Generated by the adapter and stored nowhere.
    const GENERATED: &[u8] = b"/proc/self/status\0";
    /// A directory inside the *writable* one, where everything else about
    /// `O_TRUNC` works. The adapter skipped the flag here on the grounds that
    /// a directory has no blocks to free, which is true and is not the
    /// question the caller asked.
    const MADE: &[u8] = b"/tmp/emptied\0";

    let mut line = Line::new();
    line.put(b"hosted refuse ");

    if (syscall(nr::MKDIR, MADE.as_ptr() as u64, 0o755, 0) as i64) < 0 {
        line.put(b"could not make a directory to refuse\n");
        line.flush();
        return;
    }

    let cases: [(&[u8], u64, &[u8]); 4] = [
        (SEALED, 30, b"a read-only file"),
        (ROOT, 21, b"the root directory"),
        (GENERATED, 13, b"a generated file"),
        (MADE, 21, b"a writable directory"),
    ];
    for (path, wanted, what) in cases {
        let answered = syscall(
            nr::OPEN,
            path.as_ptr() as u64,
            open::RDONLY | open::TRUNC,
            0,
        );
        if (answered as i64) >= 0 {
            syscall(nr::CLOSE, answered, 0, 0);
            line.put(b"O_TRUNC ON ");
            line.put(what);
            line.put(b" WAS ACCEPTED\n");
            line.flush();
            return;
        }
        if answered.wrapping_neg() != wanted {
            line.put(what);
            line.put(b" answered errno ");
            line.number(answered.wrapping_neg());
            line.put(b", wanted ");
            line.number(wanted);
            line.put(b"\n");
            line.flush();
            return;
        }
    }

    // **And the file still has its bytes.** A refusal that emptied it on the
    // way out would be worse than the silence it replaced.
    let back = syscall(nr::OPEN, SEALED.as_ptr() as u64, open::RDONLY, 0);
    if (back as i64) < 0 {
        line.put(b"the read-only file could not be reopened\n");
        line.flush();
        return;
    }
    let mut buffer = [0u8; 64];
    let read = syscall(
        nr::READ,
        back,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    syscall(nr::CLOSE, back, 0, 0);
    if (read as i64) <= 0 {
        line.put(b"the read-only file is EMPTY after the refusal\n");
        line.flush();
        return;
    }

    for (path, _, what) in cases {
        let opened = syscall(nr::OPEN, path.as_ptr() as u64, open::RDONLY, 0);
        if (opened as i64) < 0 {
            line.put(what);
            line.put(b" cannot be opened at all, so the refusal proves nothing\n");
            line.flush();
            return;
        }
        syscall(nr::CLOSE, opened, 0, 0);
    }

    line.put(b"ok: EROFS, EISDIR, EACCES and EISDIR again, ");
    line.number(read);
    line.put(b" bytes still in the read-only file, all four open without it\n");
    line.flush();
}

/// RFC 0077: `> file` over a longer file leaves nothing of the longer one.
///
/// **The assertion is what is *not* there.** A truncate that frees nothing
/// looks identical from the write side -- the short body is written, the call
/// returns the right count -- and only shows up as the old tail surviving past
/// its end. So this writes a long body, reopens with `O_TRUNC`, writes a short
/// one, and reads back *more* than it wrote: the bytes past the short body must
/// be absent, not merely different.
fn truncate_over_a_longer_file() {
    const PATH: &[u8] = b"/tmp/trunc\0";
    const LONG: &[u8] = b"this is the longer body that truncation has to remove completely";
    const SHORT: &[u8] = b"short";

    let mut line = Line::new();
    line.put(b"hosted trunc ");

    let fd = syscall(
        nr::OPEN,
        PATH.as_ptr() as u64,
        open::WRONLY | open::CREAT,
        0o644,
    );
    if (fd as i64) < 0
        || syscall(nr::WRITE, fd, LONG.as_ptr() as u64, LONG.len() as u64) != LONG.len() as u64
    {
        line.put(b"could not write the long body\n");
        line.flush();
        return;
    }
    syscall(nr::CLOSE, fd, 0, 0);

    let over = syscall(
        nr::OPEN,
        PATH.as_ptr() as u64,
        open::WRONLY | open::TRUNC,
        0o644,
    );
    if (over as i64) < 0 {
        line.put(b"reopen with O_TRUNC refused errno ");
        line.number(over.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let wrote = syscall(nr::WRITE, over, SHORT.as_ptr() as u64, SHORT.len() as u64);
    syscall(nr::CLOSE, over, 0, 0);
    if wrote != SHORT.len() as u64 {
        line.put(b"short body did not go\n");
        line.flush();
        return;
    }

    let back = syscall(nr::OPEN, PATH.as_ptr() as u64, open::RDONLY, 0);
    if (back as i64) < 0 {
        line.put(b"reopen refused errno ");
        line.number(back.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let mut buffer = [0u8; 128];
    // Asks for far more than the short body, so a surviving tail is read
    // rather than left outside the window.
    let read = syscall(
        nr::READ,
        back,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    syscall(nr::CLOSE, back, 0, 0);
    if (read as i64) != SHORT.len() as i64 {
        line.put(b"read back ");
        line.number(read);
        line.put(b" bytes, wanted ");
        line.number(SHORT.len() as u64);
        line.put(b" -- the old body is still there\n");
        line.flush();
        return;
    }
    if &buffer[..SHORT.len()] != SHORT {
        line.put(b"read back the wrong bytes\n");
        line.flush();
        return;
    }
    // **And the same thing through `ftruncate`, because `O_TRUNC` proving the
    // service works does not prove the call a program actually holds does.**
    // A shell redirects with `O_TRUNC`; anything that keeps a descriptor and
    // empties it in place uses this one, and it is a different arm of the
    // adapter reaching the same method.
    let again = syscall(nr::OPEN, PATH.as_ptr() as u64, open::WRONLY, 0o644);
    if (again as i64) < 0 {
        line.put(b"reopen for ftruncate refused errno ");
        line.number(again.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    if syscall(nr::WRITE, again, LONG.as_ptr() as u64, LONG.len() as u64) != LONG.len() as u64 {
        line.put(b"could not write the long body again\n");
        line.flush();
        return;
    }
    // A length this system cannot honour is refused rather than rounded to
    // zero: a program that asked to keep the first five bytes and got an empty
    // file is worse off than one told the call is unavailable.
    let refused = syscall(nr::FTRUNCATE, again, 5, 0);
    if (refused as i64) != -22 {
        line.put(b"ftruncate to a non-zero length answered ");
        line.number(refused.wrapping_neg());
        line.put(b", wanted EINVAL\n");
        line.flush();
        return;
    }
    if syscall(nr::FTRUNCATE, again, 0, 0) != 0 {
        line.put(b"ftruncate to zero was refused\n");
        line.flush();
        return;
    }
    syscall(nr::CLOSE, again, 0, 0);

    let after = syscall(nr::OPEN, PATH.as_ptr() as u64, open::RDONLY, 0);
    if (after as i64) < 0 {
        line.put(b"reopen after ftruncate refused\n");
        line.flush();
        return;
    }
    let mut empty = [0u8; 128];
    let left = syscall(
        nr::READ,
        after,
        empty.as_mut_ptr() as u64,
        empty.len() as u64,
    );
    syscall(nr::CLOSE, after, 0, 0);
    if left != 0 {
        line.put(b"ftruncate left ");
        line.number(left);
        line.put(b" bytes behind\n");
        line.flush();
        return;
    }

    line.put(b"ok: a longer body was emptied, ");
    line.number(read);
    line.put(b" bytes left and nothing past them; ftruncate emptied it again\n");
    line.flush();
}

/// RFC 0060 step 4: `mkdir` and `unlink` under the writable directory.
///
/// **The unlink is checked by trying to open what it removed**, not by its own
/// return value. A `REMOVE_AT` that answered `OK` and freed nothing would look
/// identical from here, and the file it left behind would be found by a later
/// boot rather than by this gate.
///
/// `mkdir` and `unlink` are the plain forms, not the `at` ones, because a
/// static BusyBox emits these numbers -- so this exercises the path `rm` and
/// `mkdir` actually take rather than the one a libc wrapper might.
fn change_the_directory() {
    const MADE: &[u8] = b"/tmp/made\0";
    const PATH: &[u8] = b"/tmp/hosted.txt\0";
    /// A file under the read-only root, which `unlink` must not remove.
    const SEALED: &[u8] = b"/inner\0";

    let mut line = Line::new();
    line.put(b"hosted change ");

    let made = syscall(nr::MKDIR, MADE.as_ptr() as u64, 0o755, 0);
    if (made as i64) < 0 {
        line.put(b"mkdir refused errno ");
        line.number(made.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    let gone = syscall(nr::UNLINK, PATH.as_ptr() as u64, 0, 0);
    if (gone as i64) < 0 {
        line.put(b"unlink refused errno ");
        line.number(gone.wrapping_neg());
        line.put(b"\n");
        line.flush();
        return;
    }
    // What says the unlink was real: the name must no longer resolve.
    let after = syscall(nr::OPEN, PATH.as_ptr() as u64, open::RDONLY, 0);
    if (after as i64) >= 0 {
        syscall(nr::CLOSE, after, 0, 0);
        line.put(b"unlinked but STILL THERE\n");
        line.flush();
        return;
    }
    // And the read-only root keeps its own: an `unlink` there must be refused
    // for the same structural reason a write is.
    let sealed = syscall(nr::UNLINK, SEALED.as_ptr() as u64, 0, 0);
    if (sealed as i64) >= 0 {
        line.put(b"REMOVED A FILE FROM THE READ-ONLY ROOT\n");
        line.flush();
        return;
    }
    line.put(b"ok: made a directory, removed a file, and the root kept its own errno ");
    line.number(sealed.wrapping_neg());
    line.put(b"\n");
    line.flush();
}

// The System V entry stub. `rsp` points at the initial process image, and it
// must be read *before* anything else touches the stack — so the first
// instruction hands it to Rust and the second aligns what is left.
core::arch::global_asm!(
    ".pushsection .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    "xor rbp, rbp",
    "mov rdi, rsp",
    "and rsp, -16",
    "call hosted_main",
    "ud2",
    ".popsection",
);
