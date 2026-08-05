// SPDX-License-Identifier: Apache-2.0
//! A shell that runs in ring 3 and asks for everything it does.
//!
//! The kernel shell (`kernel/src/shell.rs`) reads a file by calling the
//! filesystem. This one cannot: it has no filesystem, no console, and no way
//! to reach either except by sending a message through a capability it was
//! given. If the capability is revoked while it runs, the command that needed
//! it starts failing and the rest keep working — which is the entire point of
//! building both shells, and is worth typing at the machine to watch.
//!
//! # What it is given
//!
//! Two capabilities, in slots this program does not choose:
//!
//! - slot 0, an endpoint reaching the console service
//! - slot 1, an endpoint reaching the filesystem service
//!
//! Everything below is those two, four registers at a time.
//!
//! # What it does not have
//!
//! No allocator, no `std`, no runtime, and no way to obtain any of them. Every
//! buffer here is a fixed-size array on the stack the kernel mapped for it. A
//! program that cannot allocate cannot exhaust memory, which is not a design
//! goal so much as an honest description of how little a first user program
//! needs.

#![no_std]
#![no_main]

use bhaskix_abi::{
    CHUNK_BYTES, Chunk, Edit, LineEditor, console, entry_of, fs, method, outcome, status, syscall,
};

/// The capability slot the console endpoint was installed in.
const CONSOLE: u64 = 0;
/// The capability slot the filesystem endpoint was installed in.
const FILESYSTEM: u64 = 1;
/// Memory this program holds and may write.
///
/// Slot 2 is left empty deliberately: `caps` reports it as "no authority", and
/// a program that held something in every slot could not show what not holding
/// one looks like.
const MEMORY_RW: u64 = 3;
/// The same memory, read-only. Same object, weaker capability.
const MEMORY_RO: u64 = 4;
/// One page of the block device's registers, read-only.
const DEVICE_WINDOW: u64 = 5;

/// What a system call returned: the status, and the message's four registers.
struct Reply {
    status: u64,
    args: [u64; 4],
}

impl Reply {
    /// Whether the call reached the service at all.
    fn delivered(&self) -> bool {
        self.status == status::OK
    }

    /// What the service said about the request.
    fn outcome(&self) -> u64 {
        bhaskix_abi::outcome_of(self.args[0])
    }

    fn chunk(&self) -> Chunk {
        Chunk::unpack(&self.args)
    }
}

/// Makes a system call.
///
/// The register assignment is `docs/rfc/0008-syscall-and-ipc-shape.md`'s:
/// `rax` kind, `rdi` capability, `rsi` method, then `rdx`, `r10`, `r8`, `r9`.
/// `r10` rather than `rcx` because `syscall` destroys `rcx`, and `r11` because
/// it destroys that too — so both are declared clobbered.
fn syscall(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> Reply {
    let status: u64;
    let (mut a0, mut a1, mut a2, mut a3) = (args[0], args[1], args[2], args[3]);

    // SAFETY: `syscall` is the only way out of ring 3 and cannot corrupt this
    // program's memory: the kernel reads its arguments from registers and
    // never from an address this program supplies. The clobbers name every
    // register the instruction destroys.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            in("rdi") capability,
            in("rsi") method,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Reply {
        status,
        args: [a0, a1, a2, a3],
    }
}

/// Sends a message to `capability` and waits for the answer.
fn call(capability: u64, method: u64, args: [u64; 4]) -> Reply {
    syscall(bhaskix_abi::syscall::CALL, capability, method, args)
}

/// Ends this program. Never returns.
fn exit() -> ! {
    syscall(bhaskix_abi::syscall::EXIT, 0, 0, [0; 4]);
    // The kernel does not return from `Exit`. If it ever did, stopping here is
    // better than running into whatever follows.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Writes bytes to the console, one chunk per round trip.
fn write(bytes: &[u8]) {
    let mut rest = bytes;
    loop {
        let (chunk, tail) = Chunk::take(rest);
        let reply = call(CONSOLE, console::WRITE, chunk.pack(0));
        if !reply.delivered() {
            // Nowhere to report this: the thing that failed is the way to
            // report things. Giving up on the write is all there is.
            return;
        }
        if tail.is_empty() {
            return;
        }
        rest = tail;
    }
}

/// Writes a decimal number.
fn write_number(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut length = 0;
    loop {
        digits[digits.len() - 1 - length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write(&digits[digits.len() - length..]);
}

/// Writes a number right-aligned in `width` columns.
fn write_padded(value: u64, width: usize) {
    let mut digits = 1;
    let mut scratch = value;
    while scratch >= 10 {
        scratch /= 10;
        digits += 1;
    }
    for _ in digits..width {
        write(b" ");
    }
    write_number(value);
}

/// Reads whatever has been typed, blocking until something has.
fn read(buffer: &mut [u8; CHUNK_BYTES]) -> usize {
    let reply = call(CONSOLE, console::READ, [0; 4]);
    if !reply.delivered() {
        return 0;
    }
    let chunk = reply.chunk();
    buffer[..chunk.len()].copy_from_slice(chunk.bytes());
    chunk.len()
}

/// Sends a path to the filesystem service, a chunk at a time.
///
/// Returns whether every chunk arrived. A path sent in pieces that stops
/// half-way would leave the service holding a prefix — which is why the
/// service resolves nothing until an operation asks it to.
fn send_path(path: &[u8]) -> bool {
    let mut rest = path;
    loop {
        let (chunk, tail) = Chunk::take(rest);
        let reply = call(FILESYSTEM, fs::PATH, chunk.pack(0));
        if !reply.delivered() {
            return false;
        }
        if tail.is_empty() {
            return true;
        }
        rest = tail;
    }
}

/// Explains why a call did not happen, using the status the kernel returned.
///
/// The distinction this prints is the one the milestone is about. "no
/// authority" means the kernel refused before the service was reached: the
/// capability was revoked, or never there. Everything else means the service
/// answered and said no.
fn report_refusal(what: &[u8], reply: &Reply) {
    write(b"  ");
    write(what);
    match reply.status {
        status::REVOKED => write(b": no authority -- the capability was revoked\n"),
        status::NO_SUCH_CAPABILITY => write(b": no authority -- nothing in that slot\n"),
        status::NO_SUCH_METHOD => write(b": the service does not answer that\n"),
        _ => {
            write(b": refused, status ");
            write_number(reply.status);
            write(b"\n");
        }
    }
}

fn report_outcome(what: &[u8], code: u64) {
    write(b"  ");
    write(what);
    match code {
        outcome::NOT_FOUND => write(b": no such file\n"),
        outcome::BAD_PATH => write(b": not a path this filesystem will resolve\n"),
        outcome::WRONG_KIND => write(b": not a file\n"),
        outcome::NOTHING_OPEN => write(b": nothing is open\n"),
        outcome::BUSY => write(b": the service has no room for another caller\n"),
        outcome::UNIDENTIFIED => write(b": the service cannot tell who is asking\n"),
        _ => write(b": refused\n"),
    }
}

fn help() {
    write(b"  commands\n");
    write(b"    help              this list\n");
    write(b"    echo <words>      print the arguments\n");
    write(b"    ls [path]         list a directory\n");
    write(b"    cat <path>        print a file\n");
    write(b"    caps              what this program is allowed to do\n");
    write(
        b"    map               map memory this program holds, and be refused what it does not\n",
    );
    write(b"    exit              end this shell\n");
    write(b"\n");
    write(b"  this shell runs in ring 3. it holds two capabilities -- one for\n");
    write(b"  the console, one for the filesystem -- and can do nothing that\n");
    write(b"  is not one of them.\n");
}

/// Reports what each capability slot answers.
///
/// A program cannot read its own CSpace — there is no system call for it, and
/// there should not be one, because a capability is authority rather than
/// information. What it *can* do is try, and see what the kernel says. Slot 2
/// is empty, and its refusal is the interesting line: it comes from the kernel
/// before any service is reached, and it looks nothing like a service saying
/// no.
fn capabilities() {
    for (slot, name) in [
        (CONSOLE, b"0  console   ".as_slice()),
        (FILESYSTEM, b"1  files     ".as_slice()),
        (2, b"2  (nothing) ".as_slice()),
    ] {
        write(b"  ");
        write(name);
        // A method no service answers, so a capability that *is* there
        // replies "no such method" rather than doing something. Asking a
        // real question to find out whether one may ask is how a probe
        // becomes an action.
        let reply = call(slot, u64::MAX, [0; 4]);
        match reply.status {
            status::OK => write(b"reachable\n"),
            status::REVOKED => write(b"revoked\n"),
            status::NO_SUCH_CAPABILITY => write(b"no authority\n"),
            _ => {
                write(b"status ");
                write_number(reply.status);
                write(b"\n");
            }
        }
    }
}

/// Maps memory this program holds, and is refused memory it does not.
///
/// The first thing a driver in a domain needs. Its descriptor rings are memory
/// it holds and the device reaches by device address; it cannot fill them in
/// without being able to see them, and `ATTACH` is how it comes to see them —
/// at an address of its own choosing, from frames the object supplies rather
/// than any it names.
///
/// Both halves are here on purpose. Slot 3 may be written and slot 4 names the
/// *same memory* read-only, so asking for a writable mapping of slot 4 tests
/// the right and not the lookup: a refusal that came from "no such capability"
/// would prove nothing about rights.
fn map() {
    const WRITABLE_AT: u64 = 0x3000_0000;
    const READ_ONLY_AT: u64 = 0x3100_0000;
    const DEVICE_AT: u64 = 0x3200_0000;
    const PATTERN: u64 = 0x5041_5454_4552_4e21;

    let attach = |slot: u64, at: u64, writable: u64| {
        syscall(syscall::INVOKE, slot, method::ATTACH, [at, writable, 0, 0]).status
    };

    write(b"  3  memory rw  ");
    if attach(MEMORY_RW, WRITABLE_AT, 1) == status::OK {
        let cell = WRITABLE_AT as *mut u64;
        // SAFETY: the kernel mapped four pages of memory this program holds,
        // writable, at exactly this address, and nothing else in this program
        // uses it. The mapping either happened or the status above was not
        // `OK`, which is the branch this is inside.
        let read_back = unsafe {
            core::ptr::write_volatile(cell, PATTERN);
            core::ptr::read_volatile(cell)
        };
        if read_back == PATTERN {
            write(b"mapped and holds what was written\n");
        } else {
            write(b"mapped but did not keep the value\n");
        }
    } else {
        write(b"could not be mapped\n");
    }

    write(b"  4  memory ro  ");
    match attach(MEMORY_RO, READ_ONLY_AT, 1) {
        status::INSUFFICIENT_RIGHTS => write(b"refused a writable mapping\n"),
        status::OK => write(b"WRITABLE, which it should not be\n"),
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
        }
    }

    // The block device's registers. A page of hardware, reached from ring 3
    // through a capability and through nothing else: this program cannot name
    // a physical address, cannot ask for a different page, and cannot write to
    // this one.
    write(b"  5  device ro  ");
    if attach(DEVICE_WINDOW, DEVICE_AT, 0) == status::OK {
        // The virtio 1.0 common configuration structure. `device_status` is
        // what the kernel's driver left there, so a value of 15 -- acknowledge,
        // driver, features-ok, driver-ok -- is the device agreeing that a
        // driver brought it up. Reading it here proves the mapping reaches the
        // hardware and not a copy of it.
        //
        // SAFETY: the kernel mapped one page of device registers, read-only
        // and uncached, at exactly this address. The offset is inside that
        // page, and this is a read of a register that reading does not change.
        let device_status = unsafe { core::ptr::read_volatile((DEVICE_AT + 0x14) as *const u8) };
        write(b"status ");
        write_number(u64::from(device_status));
        write(b"\n");
    } else {
        write(b"could not be mapped\n");
    }

    write(b"  5  device rw  ");
    match attach(DEVICE_WINDOW, DEVICE_AT + 0x1000, 1) {
        status::INSUFFICIENT_RIGHTS => write(b"refused a writable mapping\n"),
        status::OK => write(b"WRITABLE, which it should not be\n"),
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
        }
    }
}

fn list(path: &[u8]) {
    let _ = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !send_path(path) {
        write(b"  ls: could not reach the filesystem\n");
        return;
    }

    let mut name = [0u8; 64];
    let mut length = 0;
    let mut entries = 0;

    loop {
        let reply = call(FILESYSTEM, fs::LIST, [0; 4]);
        if !reply.delivered() {
            report_refusal(b"ls", &reply);
            return;
        }
        if reply.outcome() != outcome::OK {
            report_outcome(b"ls", reply.outcome());
            return;
        }

        let chunk = reply.chunk();
        if chunk.is_empty() {
            break;
        }

        // A name longer than one chunk arrives across several. Assembling it
        // here rather than printing the pieces is what stops a long name from
        // looking like two short ones.
        let room = name.len() - length;
        let taken = chunk.len().min(room);
        name[length..length + taken].copy_from_slice(&chunk.bytes()[..taken]);
        length += taken;

        if chunk.more() {
            continue;
        }

        let (size, directory) = entry_of(reply.args[3]);
        write(b"  ");
        write_padded(size, 8);
        write(b"  ");
        write(&name[..length]);
        if directory {
            write(b"/");
        }
        write(b"\n");
        length = 0;
        entries += 1;
    }

    if entries == 0 {
        write(b"  nothing there\n");
    }
}

fn cat(path: &[u8]) {
    let _ = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !send_path(path) {
        write(b"  cat: could not reach the filesystem\n");
        return;
    }

    let opened = call(FILESYSTEM, fs::OPEN, [0; 4]);
    if !opened.delivered() {
        report_refusal(b"cat", &opened);
        return;
    }
    if opened.outcome() != outcome::OK {
        report_outcome(b"cat", opened.outcome());
        return;
    }

    let mut last = b'\n';
    loop {
        let reply = call(FILESYSTEM, fs::READ, [0; 4]);
        if !reply.delivered() {
            report_refusal(b"cat", &reply);
            return;
        }
        let chunk = reply.chunk();
        if chunk.is_empty() {
            break;
        }
        last = chunk.bytes()[chunk.len() - 1];
        write(chunk.bytes());
    }
    // A newline only if the file lacked one, so the prompt starts a line
    // without a blank one before it.
    if last != b'\n' {
        write(b"\n");
    }
}

/// Splits a line into a command and the rest.
fn split(line: &[u8]) -> (&[u8], &[u8]) {
    let start = line.iter().position(|b| !b.is_ascii_whitespace());
    let Some(start) = start else {
        return (b"", b"");
    };
    let line = &line[start..];
    match line.iter().position(u8::is_ascii_whitespace) {
        Some(end) => {
            let rest = &line[end..];
            let offset = rest
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(rest.len());
            (&line[..end], &rest[offset..])
        }
        None => (line, b""),
    }
}

fn run(line: &[u8]) {
    let (command, rest) = split(line);
    match command {
        b"" => {}
        b"help" => help(),
        b"echo" => {
            write(rest);
            write(b"\n");
        }
        b"ls" => list(rest),
        b"caps" => capabilities(),
        b"map" => map(),
        b"cat" => {
            if rest.is_empty() {
                write(b"  cat: which file?\n");
            } else {
                cat(rest);
            }
        }
        b"exit" => {
            write(b"  ending the shell.\n");
            exit();
        }
        other => {
            write(b"  ");
            write(other);
            write(b": not a command. Try 'help'.\n");
        }
    }
}

const PROMPT: &[u8] = b"bhaskix$ ";

/// The shell.
///
/// `extern "C"` and `no_mangle` because the entry stub below calls it by name.
#[unsafe(no_mangle)]
extern "C" fn shell_main() -> ! {
    write(b"\n  a user-mode shell. 'help' lists what it can do.\n");
    write(PROMPT);

    let mut editor = LineEditor::new();
    let mut buffer = [0u8; CHUNK_BYTES];

    loop {
        let read = read(&mut buffer);
        if read == 0 {
            // The console is gone. Nothing this program does afterwards could
            // be seen, so there is no point continuing to do it.
            exit();
        }

        for byte in buffer.iter().take(read) {
            match editor.accept(*byte) {
                Edit::Inserted(byte) => write(&[byte]),
                // Back over the character, a space where it was, back again.
                // A lone backspace only moves the cursor.
                Edit::Erased => write(b"\x08 \x08"),
                Edit::Cancelled => {
                    write(b"^C\n");
                    write(PROMPT);
                }
                Edit::Complete => {
                    write(b"\n");
                    run(editor.line());
                    editor.clear();
                    write(PROMPT);
                }
                Edit::Ignored => {}
            }
        }
    }
}

/// There is nothing to unwind and nothing to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A program in ring 3 has
    // no other way to stop that does not depend on the kernel accepting a
    // system call, and a panicking program should not depend on anything.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

// The entry point.
//
// The kernel enters here with the stack pointer at the top of the one page it
// mapped and nothing else set. `rbp` is cleared so a debugger walking the
// frame chain stops here rather than following whatever was in the register,
// and the stack is aligned because the ABI promises a callee that it is.
core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call shell_main
    ud2
"#
);
