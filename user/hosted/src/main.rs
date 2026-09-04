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
    /// `execve(path, argv, envp)`.
    pub const EXECVE: u64 = 59;
}

/// `open` flags, from this machine's own headers.
mod open {
    /// Write only.
    pub const WRONLY: u64 = 0o1;
    /// Create if absent.
    ///
    /// **Not used, and kept deliberately.** Opening with it works — a hosted
    /// program gets a real file and `fd 3` — but the journalled write that
    /// follows reproducibly reddens the TCP inbound gate: 5 boots of 5 with
    /// it, 3 of 3 without. It is measured in TRACKER §3 as a lever on that
    /// defect, and this constant is what the next person flips to reproduce
    /// it in one line.
    #[allow(dead_code, reason = "the lever for TRACKER §3's TCP measurement")]
    pub const CREAT: u64 = 0o100;
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

    // RFC 0060, step 2 in isolation: **open only, no write.** The bisect said
    // exercising the write path breaks an unrelated socket gate, and which
    // half does it was never established -- so this half runs alone.
    open_only();

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

/// Opens a file under the writable directory and closes it. Nothing is
/// written: this exists to say whether the *open* alone is what disturbs the
/// machine.
fn open_only() {
    const PATH: &[u8] = b"/tmp/hosted.txt\0";

    let mut line = Line::new();
    line.put(b"hosted open ");
    let fd = syscall(
        nr::OPEN,
        PATH.as_ptr() as u64,
        open::WRONLY, // BISECT: no CREAT, so no journalled write
        0o644,
    );
    if (fd as i64) < 0 {
        line.put(b"refused errno ");
        line.number(fd.wrapping_neg());
    } else {
        line.put(b"ok fd ");
        line.number(fd);
        syscall(nr::CLOSE, fd, 0, 0);
    }
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
