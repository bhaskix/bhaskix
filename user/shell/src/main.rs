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
/// A notification this program may wait on.
const SIGNAL: u64 = 6;
/// The same notification, with the write right and not the read right.
const SIGNAL_WRITE_ONLY: u64 = 7;
/// One directory of the filesystem — `sub`, and not the root.
///
/// This program has no capability naming the directory above it, and there is
/// no method that would take a path to one. What it can reach is what is
/// *inside* this directory, which is one name.
const DIRECTORY: u64 = 8;
/// Where [`open`] puts what it opened. Emptied again afterwards.
const OPENED: u64 = 9;
/// The same directory as [`DIRECTORY`], one generation on.
///
/// What a capability looks like after the directory it named has been freed
/// and its inode reused. Nothing on this machine writes to a filesystem yet,
/// so the kernel manufactures one — the check that catches these should be
/// working *before* the step that makes them happen for real.
const STALE_DIRECTORY: u64 = 10;

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
    write(b"    open <name>       resolve a name inside the directory held\n");
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

    // The directory, asked differently on purpose. The three above are
    // endpoints and are probed with a message; this one is not a service, so
    // it is probed with an invocation of a method it does not answer. A
    // capability that is there says "no such method" -- which is the kernel
    // refusing an operation on an object it found. A capability that is not
    // there says "no such capability", from earlier, without ever looking at
    // the method. Two refusals that mean opposite things.
    write(b"  8  directory ");
    let reply = syscall(syscall::INVOKE, DIRECTORY, u64::MAX, [0; 4]);
    match reply.status {
        status::NO_SUCH_METHOD => write(b"reachable, and answers no method it was not given\n"),
        status::NO_SUCH_CAPABILITY => write(b"no authority\n"),
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
        }
    }

    // The stale one, and this probe has to be a real lookup. A capability that
    // has outlived what it named is indistinguishable from a live one until it
    // is used -- the generation is checked against the filesystem, not against
    // anything the CSpace knows -- so asking whether the slot is occupied
    // would answer yes and prove nothing.
    write(b"  10 stale dir ");
    let (chunk, _) = Chunk::take(b"inner");
    let reply = syscall(
        syscall::INVOKE,
        STALE_DIRECTORY,
        method::OPEN_AT,
        chunk.pack(OPENED),
    );
    match reply.status {
        status::REVOKED => write(b"the directory it named is gone\n"),
        status::OK => write(b"resolved -- the generation was not checked\n"),
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
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

/// Waits on a notification, and is refused one it may not take from.
///
/// The last thing a driver in a domain needs. Its device raises an interrupt,
/// the kernel masks the source and signals a notification, and the driver
/// wakes here — holding no vector, no interrupt controller and no way to reach
/// either. This program is woken by the kernel rather than by a device, which
/// is the same last link: what a device causes is the *signal*, and that an
/// interrupt reaches a notification is gated where the interrupt is.
fn signals() {
    write(b"  6  signal rd  ");
    let woken = syscall(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
    if woken.status == status::OK {
        write(b"woke with badge ");
        write_number(woken.args[0]);
        write(b"\n");
    } else {
        write(b"status ");
        write_number(woken.status);
        write(b"\n");
    }

    // Taken means taken. A notification is a signal and not a queue, so the
    // second look finds nothing rather than the same wake again.
    write(b"  6  signal rd  ");
    let again = syscall(syscall::INVOKE, SIGNAL, method::PEEK, [0; 4]);
    if again.status == status::OK && again.args[0] == 0 {
        write(b"nothing left after taking it\n");
    } else {
        write(b"still ");
        write_number(again.args[0]);
        write(b"\n");
    }

    // The same notification, through a capability that may not take from it.
    write(b"  7  signal wr  ");
    match syscall(syscall::INVOKE, SIGNAL_WRITE_ONLY, method::PEEK, [0; 4]).status {
        status::INSUFFICIENT_RIGHTS => write(b"refused a take\n"),
        status::OK => write(b"TOOK, which it should not\n"),
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

/// Resolves one name inside the directory this program holds.
///
/// The point of the command is what it *cannot* do. There is no path to give
/// it: `sub/inner` is refused, because a name with a separator in it is a name
/// this system does not resolve. There is no `..`, so the directory above --
/// which exists, and holds files -- is unreachable from here. And a name that
/// is on the same filesystem but in that directory above comes back as "no
/// such name", the same answer as a name that is nowhere at all, because a
/// program that could tell those apart could map a filesystem it was never
/// given by asking about it one name at a time.
///
/// What comes back is a capability, in a slot named here. Asking its size is a
/// second invocation on *that* capability -- so the size is proof the thing
/// resolved, and not a number the kernel volunteered about a name.
fn open(name: &[u8]) {
    // Whatever a previous `open` left. Dropping it first is what makes the
    // command repeatable, and `DELETE` on an empty slot is not an error.
    syscall(syscall::INVOKE, OPENED, method::DELETE, [0; 4]);

    let (chunk, rest) = Chunk::take(name);
    if !rest.is_empty() {
        // Longer than one chunk. Refused here rather than sent, because the
        // kernel would refuse it too and a name that arrived truncated would
        // open a different file.
        write(b"  open: that name is too long to send\n");
        return;
    }

    write(b"  ");
    write(name);
    write(b": ");
    let reply = syscall(
        syscall::INVOKE,
        DIRECTORY,
        method::OPEN_AT,
        chunk.pack(OPENED),
    );
    match reply.status {
        status::OK => {}
        status::NO_SUCH_NAME => {
            write(b"no such name in this directory\n");
            return;
        }
        status::BAD_NAME => {
            write(b"not a name this system resolves\n");
            return;
        }
        status::NO_SUCH_CAPABILITY => {
            write(b"nothing in that slot -- this program holds no directory\n");
            return;
        }
        status::WRONG_OBJECT => {
            write(b"not a directory to look in\n");
            return;
        }
        other => {
            write(b"refused, status ");
            write_number(other);
            write(b"\n");
            return;
        }
    }

    if reply.args[0] & method::IS_DIRECTORY != 0 {
        write(b"a directory, at slot ");
        write_number(reply.args[0] & 0xffff_ffff);
        write(b"\n");
        return;
    }

    // A file. Its size comes from the capability rather than from the lookup:
    // asking the thing that was opened is the only way to know that what
    // landed in the slot is what the name meant.
    let size = syscall(syscall::INVOKE, OPENED, method::INFO, [0; 4]);
    if size.status == status::OK {
        write(b"a file of ");
        write_number(size.args[0]);
        write(b" bytes, at slot ");
        write_number(reply.args[0] & 0xffff_ffff);
        write(b"\n");
    } else {
        write(b"opened, but it will not say how big it is\n");
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
        b"open" => {
            if rest.is_empty() {
                write(b"  open: which name?\n");
            } else {
                open(rest);
            }
        }
        b"caps" => capabilities(),
        b"map" => map(),
        b"irq" => signals(),
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
