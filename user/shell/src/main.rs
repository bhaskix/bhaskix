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
    CHUNK_BYTES, Chunk, Edit, LineEditor, block, console, dir, entry_of, fs, method, outcome,
    rights, socket, status, syscall,
};

/// The capability slot the console endpoint was installed in.
const CONSOLE: u64 = 0;
/// The capability slot the filesystem endpoint was installed in.
const FILESYSTEM: u64 = 1;
/// Authority to create a domain — RFC 0017's first unresolved question,
/// answered on 2026-08-11.
///
/// Holding it is not sufficient on its own: the envelope allows one child, so
/// a second `spawn` is refused for the budget rather than for this. Those are
/// different refusals and the shell reports them differently.
const DOMAIN_CONTROL: u64 = 14;
/// Where [`spawn`] puts the domain it makes. Given back with `RELEASE`.
const CHILD: u64 = 15;
/// The one *writable* directory this program holds: `/pkg`, and nothing
/// above it (RFC 0030 step 3). Absent on a machine whose filesystem could
/// not make it, and `pkg` commands then refuse with the slot empty.
const PKG_DIR: u64 = 20;
/// Sixteen pages a package archive is staged in: read out of the initrd,
/// verified in place, drained from one page at a time.
const STAGING: u64 = 21;
/// Working slots the `pkg` commands resolve handles into. Emptied after use.
const PKG_WORK: u64 = 22;
const PKG_WORK2: u64 = 23;
const PKG_FILE: u64 = 24;
/// Where the staging memory maps.
const STAGING_AT: u64 = 0x3700_0000;
/// Where the one-page transfer window maps for `pkg` writes — the same
/// object `map` demonstrates with, at an address of its own so the two
/// commands cannot trip each other.
const TRANSFER_AT: u64 = 0x3800_0000;
/// The badge the child's ending carries, so a wake can be told from any other.
const CHILD_BADGE: u64 = 0xc1d;
/// At most this much of a file is read in as an image.
///
/// The shell's memory object is four pages, and this is all of it. A larger
/// program is refused rather than truncated: half an ELF is not a program, and
/// starting one would fail somewhere less obvious than here.
const IMAGE_LIMIT: u64 = 4 * 4096;
/// The name the child is created with, packed little-endian: `child`.
const NAME_LOW: u64 = 0x0064_6c69_6863;
const NAME_HIGH: u64 = 0;
/// Every right this program holds, which is what a grant may pass on at most.
///
/// Named rather than spelled `READ | WRITE`: a child given only those two could
/// not derive or pass on what it was handed, and the failure of a grant that is
/// too narrow is a program that starts, does nothing, and exits cleanly -- which
/// looks exactly like a program that was never given anything.
const EVERYTHING_HELD: u64 = rights::READ
    | rights::WRITE
    | rights::EXECUTE
    | rights::GRANT
    | rights::REVOKE
    | rights::DERIVE;

/// The badge the console gave this program, which a grant must carry unchanged.
///
/// A holder may not invent a badge: the service uses it to tell its callers
/// apart, so one a caller chose would be a caller choosing who it looks like.
const BADGE_CONSOLE: u64 = 0x0000_0000_00c0_0000;

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
/// Where a page the filesystem service lends is accepted.
const LENT_PAGE: u64 = 11;
/// Where that page is mapped, read-only.
const LENT_AT: u64 = 0x3400_0000;
/// The block service's endpoint, in another domain.
const BLOCK: u64 = 12;
/// Where a capability the block service hands over is accepted.
const LENT: u64 = 13;
/// A slot this program keeps free, to find things out with.
///
/// A probe that had to occupy a slot it cared about would be answering a
/// different question afterwards.
///
/// **It was 11 until 2026-08-21, which is [`LENT_PAGE`] — a slot this program
/// cares about very much.** The sentence above states the invariant and the
/// value broke it: `caps` derives into this slot twice and `DELETE`s it each
/// time, so running `caps` after an `open` silently emptied the lent-page slot
/// while leaving the page mapped. `release` then proves the page "can no
/// longer be mapped" by attaching that slot and being refused — a refusal
/// `caps` had already arranged. The boot gate escapes it only because
/// `shell-test.sh` happens to type `caps` before `open`; typing it after was
/// tried on 2026-08-21 and every gate still passed, which is the definition of
/// a gate that has stopped testing what it names. 18 is free, and is not
/// spoken about anywhere else.
const SCRATCH: u64 = 18;
/// The badge the kernel put on this program's filesystem capability.
///
/// Known here only so that the probe can ask for the *same* one. A program
/// cannot read its own badges — there is no system call for it, and there
/// should not be, because a badge is what a service is told about a caller and
/// not what the caller is told about itself.
const BADGE_FILESYSTEM: u64 = 0x0000_0000_00f5_0000;
/// The same directory as [`DIRECTORY`], one generation on.
///
/// What a capability looks like after the directory it named has been freed
/// and its inode reused. Nothing on this machine writes to a filesystem yet,
/// so the kernel manufactures one — the check that catches these should be
/// working *before* the step that makes them happen for real.
const STALE_DIRECTORY: u64 = 10;

/// Slot: the network, if this program was given one.
///
/// **The whole of what "having networking" means here.** There is no port table
/// to ask and no interface list to enumerate, so a program without this has no
/// way to name the network at all — which is not a refused call, it is nothing
/// to call. `bin/probe` holds none and never will.
const NETWORK: u64 = 16;

/// Slot: where a socket lands, declared with `EXPECT` before asking for one.
const SOCKET: u64 = 17;

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

    /// The number a **service** packed beside its outcome.
    ///
    /// `with_outcome` puts the outcome eight bits up at bit 16, so the value is
    /// what is below it. Separate from [`Reply::raw`] because a kernel invoke
    /// packs nothing: reading one with the other's accessor silently truncates
    /// or silently includes an outcome byte, and both look like a number.
    fn value(&self) -> u64 {
        self.args[0] & 0xffff
    }

    /// What a **kernel** invoke returned, which carries no outcome.
    fn raw(&self) -> u64 {
        self.args[0]
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
            // `inlateout`, not `in`. The kernel pops the whole frame back on
            // the way out -- `rsi` included -- so telling the compiler it is
            // preserved is telling it something the machine does not promise.
            // This system has been bitten by exactly that once already, for
            // the argument registers; `rsi` was the one that was missed.
            inlateout("rsi") method => _,
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

/// How many times a congested call is retried before it is reported.
///
/// Bounded, unlike the retry in `service-domain`'s `serve`. A server with a
/// congested endpoint has nothing else it could be doing, so spinning there is
/// free; a shell that retried for ever would stop answering the person typing
/// at it, and "the machine is wedged" is worse than "the service is busy".
///
/// Generous, because the failure this replaces was giving up on the **first**
/// refusal. Congestion clears when the threads ahead are served, which takes
/// as long as their work takes -- so a bound this size is the difference
/// between waiting for a queue and waiting for a deadlock.
const CONGESTION_RETRIES: u32 = 128;

/// Sends a message to `capability` and waits for the answer.
///
/// **Retries congestion**, which is the whole of this function beyond the
/// syscall. `Congested` means the endpoint's send queue was full at that
/// instant: the message was never queued, so the service never saw it. That is
/// what makes retrying safe rather than merely hopeful -- a call that returns
/// `Congested` cannot have half-happened, so sending it again cannot repeat an
/// operation. Every other status is an answer, and answers are not retried.
///
/// The yield matters as much as the loop. The queue drains when the threads
/// ahead of this one are served, and a tight retry would spend the CPU they
/// need to drain it -- which is the same reasoning `service-domain::serve`
/// gives for the same status on the receiving side.
fn call(capability: u64, method: u64, args: [u64; 4]) -> Reply {
    let mut attempts = 0;
    loop {
        let reply = syscall(bhaskix_abi::syscall::CALL, capability, method, args);
        if reply.status != status::CONGESTED || attempts >= CONGESTION_RETRIES {
            return reply;
        }
        attempts += 1;
        syscall(bhaskix_abi::syscall::YIELD, 0, 0, [0; 4]);
    }
}

/// Ends this program. Never returns.
fn exit() -> ! {
    syscall(bhaskix_abi::syscall::EXIT, 0, 0, [0; 4]);
    // The kernel does not return from `Exit`. If it ever did, stopping here is
    // better than running into whatever follows.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Prints what the kernel printed while it was booting.
///
/// **The report scrolls off a framebuffer and there is no way back to it**, and
/// on a machine whose serial is carried by a service processor there is no
/// second copy either. Both of this project's hardware boots died at exactly
/// that: the machine ran, somebody watched it, and nothing anybody needed to
/// read was still on screen. RFC 0042.
///
/// The name is the one somebody coming from Linux guesses. What it names is
/// **not** a kernel ring buffer with priorities, facilities and timestamps: it
/// is the bytes the kernel printed, in order, kept until a fixed buffer filled.
/// The help text says so, because a familiar name must not imply a guarantee
/// this system does not offer.
fn dmesg() {
    let reply = call(CONSOLE, console::RECORD_SIZE, [0; 4]);
    if !reply.delivered() {
        write(b"dmesg: the console service did not answer\n");
        return;
    }
    let size = reply.args[0] as usize;
    if size == 0 {
        write(b"dmesg: nothing recorded\n");
        return;
    }

    let mut offset = 0usize;
    let mut lines = 0usize;
    while offset < size {
        let reply = call(CONSOLE, console::RECORD, [offset as u64, 0, 0, 0]);
        if !reply.delivered() {
            write(b"\ndmesg: the record stopped answering part way\n");
            return;
        }
        let chunk = Chunk::unpack(&reply.args);
        let bytes = chunk.bytes();
        if bytes.is_empty() {
            // Past the end. Believed rather than argued with: the service and
            // the size agree, and stopping here is what a caller that trusted
            // only one of them would also do.
            break;
        }

        // **Paged, and on a real machine that is the whole point.** Without it
        // this prints twenty-one kilobytes onto a twenty-five line framebuffer
        // and scrolls past exactly like the report it exists to recover -- so
        // it would be a command that reproduces the problem it was built for.
        // A byte at a time rather than a chunk at a time, because a page break
        // lands mid-chunk far more often than not.
        for byte in bytes {
            write(core::slice::from_ref(byte));
            if *byte == b'\n' {
                lines += 1;
                if lines >= PAGE_LINES {
                    lines = 0;
                    if !more() {
                        return;
                    }
                }
            }
        }
        offset += bytes.len();
    }
}

/// How many lines `dmesg` prints before it waits.
///
/// Twenty-two of a twenty-five line framebuffer, leaving room for the prompt
/// and the line the reader is still looking at.
const PAGE_LINES: usize = 22;

/// Waits at a page break. Answers whether to carry on.
///
/// **`q` quits and anything else continues**, which is the way round somebody
/// who has used `more` expects. A reader who wanted one line near the start
/// should not have to page through the rest to get their prompt back.
fn more() -> bool {
    write(b"-- more -- (q quits) ");
    let mut buffer = [0u8; CHUNK_BYTES];
    let taken = read(&mut buffer);
    // Erase the prompt, so the record reads as a record rather than as a
    // transcript with page furniture in it.
    write(b"\r                      \r");
    taken == 0 || (buffer[0] != b'q' && buffer[0] != b'Q')
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
            //
            // This used to drop output for *congestion* too, which is a
            // console that goes quiet because it is busy -- the one cause that
            // clears on its own. `call` now retries that before returning, so
            // what reaches here is an undeliverable console rather than a
            // loaded one, and giving up is the right answer to it.
            return;
        }
        if tail.is_empty() {
            return;
        }
        rest = tail;
    }
}

/// Writes a decimal number.
/// Writes a number in hexadecimal, four digits, for identities that are read
/// that way and would be unrecognisable in decimal.
fn write_hex(value: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 4];
    for (index, cell) in out.iter_mut().enumerate() {
        *cell = DIGITS[((value >> (12 - index * 4)) & 0xf) as usize];
    }
    write(&out);
}

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
/// Sends a path to the filesystem service, one chunk per round trip.
///
/// Returns the reply that did not arrive, rather than a bare `false`. The
/// status is the only thing separating "the capability was revoked" from "the
/// service is gone" from "the kernel refused the call before either" -- and a
/// caller that answers `could not reach the filesystem` has thrown away the
/// answer to the question it is asking. That cost a soak run: `cat` failed once
/// in about seventy, printed exactly that, and left nothing to work from while
/// every kernel self-test in the same boot passed.
fn send_path(path: &[u8]) -> Result<(), Reply> {
    let mut rest = path;
    loop {
        let (chunk, tail) = Chunk::take(rest);
        let reply = call(FILESYSTEM, fs::PATH, chunk.pack(0));
        if !reply.delivered() {
            return Err(reply);
        }
        if tail.is_empty() {
            return Ok(());
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
        // Reached only after `call` has already retried this many times. The
        // count is the message: "refused, status 8" said nothing about whether
        // waiting would have helped, and waiting is exactly what was tried.
        status::CONGESTED => {
            write(b": the service is still busy after ");
            write_number(u64::from(CONGESTION_RETRIES));
            write(b" retries\n");
        }
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
    write(b"    open <name>       resolve one name in the directory held -- no paths,\n");
    write(b"                      no '..'; also maps the page the service lends\n");
    write(b"    held              print what the page lent by 'open' begins with\n");
    write(b"    release           give back the page 'open' was lent, and prove it\n");
    write(b"                      cannot be mapped again\n");
    write(b"    ask               ask the block service for a capability, and be\n");
    write(b"                      refused it until a slot is declared for it\n");
    write(b"    caps              what this program is allowed to do\n");
    write(b"    irq               wait for a signal, and report the badge it carried\n");
    write(b"    net <host>        speak to a host through the network service\n");
    write(
        b"    map               map memory this program holds, and be refused what it does not\n",
    );
    write(b"    spawn <path>      start a program in a domain of its own\n");
    write(b"    pkg install <f>   install a package onto the writable filesystem\n");
    write(b"    pkg list          what is installed\n");
    write(b"    pkg run <n>       start an installed program, grants from its manifest\n");
    write(b"    pkg remove <n>    remove an installed package\n");
    write(b"    dmesg             print what the kernel printed while booting, a\n");
    write(b"                      page at a time (q quits) --\n");
    write(b"                      the bytes themselves, in order, not a log with\n");
    write(b"                      priorities or timestamps\n");
    write(b"    exit              end this shell\n");
    write(b"\n");
    write(b"  this shell runs in ring 3 and can do nothing it does not hold a\n");
    write(b"  capability for. 'caps' lists them. one of them creates domains,\n");
    write(b"  and the envelope allows exactly one -- so a second 'spawn' is\n");
    write(b"  refused for the budget rather than for the authority.\n");
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
    // The directory is a capability to a *service* now. Probed with a method
    // it does not answer: a capability that is there is answered at all, and
    // one that is not says "no authority", from the kernel, before anything is
    // reached.
    write(b"  8  directory ");
    let reply = call(DIRECTORY, u64::MAX, [0; 4]);
    match reply.status {
        status::OK => write(b"reachable, and answers no method it was not given\n"),
        status::NO_SUCH_CAPABILITY => write(b"no authority\n"),
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
        }
    }

    // A badge, and whether this program can choose its own.
    //
    // Slot 1's capability carries a badge the kernel put there, and the
    // filesystem service uses it to tell its callers apart. Two derivations
    // are asked for and they have to answer differently, or neither means
    // anything: the same badge with weaker rights is **delegation** and must
    // work, and a different badge is **forgery** and must not. A rule that
    // refused both would look identical here to a rule that refused neither,
    // if only one of them were asked.
    let derive = |rights: u64, badge: u64, into: u64| {
        let reply = syscall(
            syscall::INVOKE,
            FILESYSTEM,
            method::DERIVE,
            [rights, badge, into, 0],
        );
        // Nothing is kept: this program is finding out what it may do, not
        // arranging to do it, and a slot left occupied would change what the
        // rest of `caps` reports.
        syscall(syscall::INVOKE, into, method::DELETE, [0; 4]);
        reply.status
    };

    write(b"  1  badge     ");
    let passed_on = derive(rights::READ, BADGE_FILESYSTEM, SCRATCH);
    let forged = derive(rights::READ, BADGE_FILESYSTEM ^ 0x5eed, SCRATCH);
    match (passed_on, forged) {
        (status::OK, status::INSUFFICIENT_RIGHTS) => {
            write(b"can be passed on, and cannot be changed by its holder\n");
        }
        (status::OK, status::OK) => write(b"FORGED -- this program chose its own badge\n"),
        (_, _) => {
            write(b"neither derivation worked, status ");
            write_number(passed_on);
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
    syscall(
        syscall::INVOKE,
        STALE_DIRECTORY,
        method::EXPECT,
        [OPENED, 0, 0, 0],
    );
    let reply = call(STALE_DIRECTORY, dir::OPEN_AT, chunk.pack(0));
    match (reply.status, reply.args[0]) {
        (status::OK, dir::GONE) => write(b"the directory it named is gone\n"),
        (status::OK, dir::OK) => write(b"resolved -- the generation was not checked\n"),
        (status::OK, other) => {
            write(b"outcome ");
            write_number(other);
            write(b"\n");
        }
        (other, _) => {
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
    let reset = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !reset.delivered() {
        report_refusal(b"ls", &reset);
        return;
    }
    if let Err(reply) = send_path(path) {
        report_refusal(b"ls", &reply);
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

/// Reads `path` into this program's memory and starts it in a domain of its own.
///
/// RFC 0017 steps 4 to 6, asked for by a person rather than by a self-test.
/// Every step is an ask on a capability this program holds, and any of them may
/// be refused — which is the point, and why each one reports separately.
///
/// **The child's own line is the assertion.** That a domain existed proves
/// `SPAWN` worked; that the child *printed* proves the `GRANT` reached it. A
/// started program holding nothing is indistinguishable from one that never
/// started, so a report of "started" and "ended" with nothing in between would
/// pass against a broken grant.
fn spawn(path: &[u8]) {
    // The image, into memory this program already holds. `READ_INTO` takes a
    // slot in *this* CSpace rather than an object identity: a caller naming an
    // identity would be asserting what it may reach, and naming a slot points
    // at authority it holds and the service checks. So this cannot read into
    // anybody else's memory, and the shell's four pages are the limit.
    let reset = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !reset.delivered() {
        report_refusal(b"spawn", &reset);
        return;
    }
    if let Err(reply) = send_path(path) {
        report_refusal(b"spawn", &reply);
        return;
    }
    let opened = call(FILESYSTEM, fs::OPEN, [0; 4]);
    if !opened.delivered() {
        report_refusal(b"spawn", &opened);
        return;
    }
    if opened.outcome() != outcome::OK {
        report_outcome(b"spawn", opened.outcome());
        return;
    }

    let filled = call(FILESYSTEM, fs::READ_INTO, [MEMORY_RW, IMAGE_LIMIT, 0, 0]);
    if !filled.delivered() {
        report_refusal(b"spawn: reading the image", &filled);
        return;
    }
    if filled.outcome() != outcome::OK {
        report_outcome(b"spawn: reading the image", filled.outcome());
        return;
    }
    let bytes = filled.value();
    if bytes == 0 {
        write(b"  spawn: the file is empty\n");
        return;
    }

    // A domain, empty. No threads, no capabilities, no address space -- which
    // is what makes the grants below the only way it gets anything.
    let made = syscall(
        syscall::INVOKE,
        DOMAIN_CONTROL,
        method::SPAWN,
        [CHILD, NAME_LOW, NAME_HIGH, 0],
    );
    if !made.delivered() {
        report_refusal(b"spawn: creating the domain", &made);
        return;
    }
    write(b"  started in a domain of its own\n");

    // The console, into the child's slot 0, under the same badge. A holder may
    // not invent a badge -- the service uses it to tell its callers apart, and
    // one a caller chose would be a caller choosing who it looks like.
    // `[from, to, rights, badge]`, which is the implementation's order and not
    // the one the kernel's doc comment gave until this change found it wrong.
    let granted = syscall(
        syscall::INVOKE,
        CHILD,
        method::GRANT,
        [CONSOLE, 0, EVERYTHING_HELD, BADGE_CONSOLE],
    );
    if !granted.delivered() {
        report_refusal(b"spawn: granting the console", &granted);
        return;
    }

    // Ask to be told it ended **before** starting it. A binding made afterwards
    // races the program: a short-lived one can be gone before its creator gets
    // round to watching, and the kernel refuses a watch for an event that has
    // already happened rather than accepting a wait that never ends.
    //
    // Bound to the notification this program already holds. `BIND` names a slot
    // that has one in it, not an empty slot to put one in -- the domain signals
    // something the caller owns, which is why a caller with no notification
    // cannot be told about anything.
    let bound = syscall(
        syscall::INVOKE,
        CHILD,
        method::BIND,
        [SIGNAL, CHILD_BADGE, 0, 0],
    );
    if !bound.delivered() {
        report_refusal(b"spawn: asking to be told it ended", &bound);
        return;
    }

    // The image arrives as a capability, not a filename: the kernel has no
    // business opening files on a program's behalf. Entry word 7 is "say so
    // through the capability you were given, and exit".
    let started = syscall(
        syscall::INVOKE,
        CHILD,
        method::START,
        [MEMORY_RW, bytes, 7, 0],
    );
    if !started.delivered() {
        report_refusal(b"spawn: starting it", &started);
        return;
    }

    // Wait for it, then ask why it ended and give the slot back.
    let ended = syscall(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
    if !ended.delivered() {
        report_refusal(b"spawn: waiting for it", &ended);
        return;
    }
    let reason = syscall(syscall::INVOKE, CHILD, method::INFO, [0; 4]);
    if reason.delivered() {
        // `raw`, not `value`: this is a kernel invoke and carries no outcome
        // byte to mask off.
        write(b"  it ended: reason ");
        write_number(reason.raw());
        write(b"\n");
    }
    let _ = syscall(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
}

fn cat(path: &[u8]) {
    let reset = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !reset.delivered() {
        report_refusal(b"cat", &reset);
        return;
    }
    if let Err(reply) = send_path(path) {
        report_refusal(b"cat", &reply);
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

/// Binds a socket, uses it, and gives it back.
///
/// RFC 0018 step 5, and the point is what the *absence* of the capability
/// means. This program holds one at [`NETWORK`]; `bin/probe` does not, and
/// there is nothing it could invoke instead — no port table, no interface
/// list, no fallback path.
///
/// The socket that comes back is a **badged capability to the protocol
/// service's own endpoint**, not an object the kernel knows about. `close`
/// then shows what the badge's second half is for: the capability keeps
/// working as a *name* and stops working as a *socket*, because the generation
/// it carries no longer matches the slot.
fn network(rest: &[u8]) {
    let (word, _) = split(rest);

    // Where a capability may land. Declared by *this* program, one-shot, and
    // the service cannot name another slot -- which is what stops a service
    // filling a slot a caller was keeping empty.
    let declared = self::syscall(syscall::INVOKE, NETWORK, method::EXPECT, [SOCKET, 0, 0, 0]);
    if declared.status != status::OK {
        write(b"  no network: expect refused with status ");
        write_number(declared.status);
        write(b"\n");
        return;
    }

    let reply = call(NETWORK, socket::BIND_UDP, [0, 0, 0, 0]);
    if reply.status != status::OK {
        write(b"  no network: the service did not answer\n");
        return;
    }
    match reply.args[0] {
        socket::NO_NETWORK => {
            write(b"  no network: there is a service but no device behind it\n");
            return;
        }
        socket::NO_PORT => {
            write(b"  no port free\n");
            return;
        }
        socket::OK => {}
        _ => {
            write(b"  the service refused\n");
            return;
        }
    }
    write(b"  bound a socket, handed back as a capability\n");

    // Use it. The datagram's contents are the service's to choose at this step;
    // what is being shown is that a *held* capability is what makes it possible.
    // A payload out of memory this program holds. `SEND_TO` reads it with
    // `DRAIN`, so a call naming no memory sends nothing.
    const PAYLOAD_AT: u64 = 0x3600_0000;
    if syscall(
        syscall::INVOKE,
        MEMORY_RW,
        method::ATTACH,
        [PAYLOAD_AT, 1, 0, 0],
    )
    .status
        == status::OK
    {
        // SAFETY: one page of memory this program holds, just mapped writable,
        // which nothing else in this program uses.
        unsafe {
            core::ptr::copy_nonoverlapping(b"ping".as_ptr(), PAYLOAD_AT as *mut u8, 4);
        }
    }
    let sent = call(
        SOCKET,
        socket::SEND_TO,
        [
            u64::from(u32::from_be_bytes([10, 0, 2, 2])),
            9,
            MEMORY_RW,
            4,
        ],
    );
    if sent.status == status::OK && sent.args[0] == socket::OK {
        write(b"  sent a datagram through it\n");
    } else {
        write(b"  the socket would not send\n");
    }

    if word == b"keep" {
        return;
    }

    let closed = call(SOCKET, socket::CLOSE, [0; 4]);
    if closed.status == status::OK && closed.args[0] == socket::OK {
        write(b"  closed it\n");
    }

    // And now the generation earns itself. The capability is still a
    // capability -- the kernel resolves it, the endpoint is still there -- and
    // the badge names a socket that no longer exists, so the service refuses
    // it. A holder that kept one across a close does not inherit whatever is
    // in that slot next.
    let stale = call(SOCKET, socket::SEND_TO, [0, 0, 0, 0]);
    if stale.status == status::OK && stale.args[0] == socket::GONE {
        write(b"  the closed socket is gone, and its slot may be somebody else's\n");
    } else {
        write(b"  a closed socket still worked -- the generation did not hold\n");
    }

    // **Give the slot back.** Closing ends the socket; it does not empty the
    // slot the capability sits in, and `HAND` cannot put anything where
    // something already is. Without this a second bind is answered `NOWHERE`,
    // which reads as the service refusing rather than as the caller not having
    // tidied up.
    let _ = syscall(syscall::INVOKE, SOCKET, method::DELETE, [0; 4]);
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
        write(b"  open: that name is too long to send\n");
        return;
    }

    // Where the answer may land, said before asking, and addressed to the
    // service being asked. Addressing it is what lets the line below be
    // printed in between: printing is a call too.
    let declared = syscall(
        syscall::INVOKE,
        DIRECTORY,
        method::EXPECT,
        [OPENED, 0, 0, 0],
    );
    if declared.status != status::OK {
        write(b"  open: this program holds no directory\n");
        return;
    }

    write(b"  ");
    write(name);
    write(b": ");
    let reply = call(DIRECTORY, dir::OPEN_AT, chunk.pack(0));
    if reply.status != status::OK {
        write(b"the filesystem service did not answer, status ");
        write_number(reply.status);
        write(b"\n");
        return;
    }
    match reply.args[0] {
        dir::NO_SUCH_NAME => {
            write(b"no such name in this directory\n");
            return;
        }
        dir::BAD_NAME => {
            write(b"not a name this system resolves\n");
            return;
        }
        dir::GONE => {
            write(b"the directory it named is gone\n");
            return;
        }
        dir::OK => {}
        other => {
            write(b"refused, outcome ");
            write_number(other);
            write(b"\n");
            return;
        }
    }

    if reply.args[2] != 0 {
        write(b"a directory, at slot ");
        write_number(OPENED);
        write(b"\n");
        return;
    }
    write(b"a file of ");
    write_number(reply.args[1]);
    write(b" bytes, at slot ");
    write_number(OPENED);
    write(b"\n");

    // And the bytes, without a copy. The service lends the page of its **own
    // cache** that the block is in, read-only, and this program maps it.
    // Nothing carried the contents here: no round trip moved them, and the
    // service never read them on this program's behalf.
    syscall(syscall::INVOKE, LENT_PAGE, method::DELETE, [0; 4]);
    let declared = syscall(
        syscall::INVOKE,
        OPENED,
        method::EXPECT,
        [LENT_PAGE, 0, 0, 0],
    );
    if declared.status != status::OK {
        return;
    }
    let lent = call(OPENED, dir::MAP, [0; 4]);
    write(b"  9  lent      ");
    if lent.status != status::OK || lent.args[0] != dir::OK {
        // With the reason. "The service would not" is the least useful thing a
        // report can say, and the service already knows why -- it answers with
        // the status that stopped it.
        write(b"the service would not lend the page, outcome ");
        write_number(lent.args[0]);
        write(b" status ");
        write_number(lent.args[1]);
        write(b"\n");
        return;
    }
    let attached = syscall(
        syscall::INVOKE,
        LENT_PAGE,
        method::ATTACH,
        [LENT_AT, 0, 0, 0],
    );
    if attached.status != status::OK {
        write(b"lent, but it would not map, status ");
        write_number(attached.status);
        write(b"\n");
        return;
    }
    // SAFETY: the kernel mapped one page read-only at exactly this address,
    // through a capability this program now holds, and nothing else in this
    // program uses it. The mapping either happened or the status above was not
    // `OK`, which is the branch this is inside.
    let head = unsafe { core::slice::from_raw_parts(LENT_AT as *const u8, 8) };
    write(b"the service's own cache page, and it begins \"");
    write(head);
    write(b"\"\n");

    // A writable mapping of it is refused: what was lent is no stronger than
    // read, whatever the service holds it with.
    let writable = syscall(
        syscall::INVOKE,
        LENT_PAGE,
        method::ATTACH,
        [LENT_AT + 0x10000, 1, 0, 0],
    );
    write(b"  11 lent page ");
    match writable.status {
        status::INSUFFICIENT_RIGHTS => write(b"refused a writable mapping\n"),
        _ => write(b"WIDENED -- a copy stronger than the original\n"),
    }
}

/// Asks a service in another domain for a capability, and uses it.
///
/// RFC 0016 step 2, end to end and with no kernel in the middle deciding
/// anything: two programs in ring 3, one of which holds a capability to a page
/// and hands the other a copy no stronger than its own. What comes back is not
/// bytes — the block service never reads the page on this program's behalf —
/// it is authority, and this program then reads the device itself.
///
/// The declaration is the part worth watching. A server cannot choose where
/// its answer lands: this program says [`LENT`] first, and a service that said
/// anything else would be putting a capability in a slot somebody else was
/// keeping empty. So the refusal below is asked for twice — once having
/// declared, and once not.
/// Ask a service for a capability, and be refused it until a slot is declared.
///
/// **Named `ask`, not `lend`, since 2026-08-21.** `lend` put this program on
/// the wrong side of its own transaction: the block service is the lender and
/// this shell is the borrower — it calls `LEND_CONFIG` and *receives*. The help
/// line had said "ask a service for a capability" since it was written, so the
/// name was the only thing still claiming otherwise.
///
/// It also stopped `lend` and `release` reading as an acquire/return pair,
/// which they never were: `release` gives back what `open` obtained from the
/// **filesystem** service, and what this command obtains from the **block**
/// service is never given back at all.
fn ask() {
    const AT: u64 = 0x3300_0000;

    // Without declaring first. Nothing may arrive, because nothing said where
    // it could go.
    let undeclared = call(BLOCK, block::LEND_CONFIG, [0; 4]);
    write(b"  undeclared    ");
    match undeclared.status {
        status::OK if undeclared.args[0] == 0 => write(b"nothing was handed over\n"),
        status::OK => write(b"HANDED ANYWAY -- into a slot never asked for\n"),
        status::NO_SUCH_CAPABILITY => {
            write(b"no block service on this machine\n");
            return;
        }
        other => {
            write(b"status ");
            write_number(other);
            write(b"\n");
            return;
        }
    }

    // And having declared. `EXPECT` names the slot; the reply says which slot
    // it landed in, and it must be the one this program asked for.
    let declared = syscall(syscall::INVOKE, BLOCK, method::EXPECT, [LENT, 0, 0, 0]);
    if declared.status != status::OK {
        write(b"  declaring    refused, status ");
        write_number(declared.status);
        write(b"\n");
        return;
    }
    let handed = call(BLOCK, block::LEND_CONFIG, [0; 4]);
    write(b"  13 lent      ");
    if handed.status != status::OK || handed.args[0] == 0 {
        write(b"the service would not hand it over\n");
        return;
    }
    if handed.args[0] - 1 != LENT {
        write(b"landed in a slot this program did not name\n");
        return;
    }

    // The capability is real or it is not, and mapping it is the only way to
    // find out. What is read back is the device's own vendor and identity from
    // its configuration space -- a number no service told this program.
    let attached = syscall(syscall::INVOKE, LENT, method::ATTACH, [AT, 0, 0, 0]);
    if attached.status != status::OK {
        write(b"mapped nothing, status ");
        write_number(attached.status);
        write(b"\n");
        return;
    }
    // SAFETY: the kernel mapped one page read-only at exactly this address,
    // through a capability this program now holds, and nothing else in this
    // program uses it. The mapping either happened or the status above was not
    // `OK`, which is the branch this is inside.
    let identity = unsafe { core::ptr::read_volatile(AT as *const u32) };
    write(b"a service handed over a page, and it reads ");
    write_hex(u64::from(identity & 0xffff));
    write(b":");
    write_hex(u64::from(identity >> 16));
    write(b"\n");

    // A capability the service holds and may not pass on. Asked *while it is
    // answering*, because outside a request it would be refused for having no
    // caller -- a different rule, and one that would make this prove nothing.
    //
    // Declared again first. A declaration is spent by the capability that
    // arrives and is dropped when its call ends, so without this the refusal
    // below would be "you did not say where", which is a third rule and would
    // prove nothing either. That is what it said the first time this was
    // written.
    syscall(syscall::INVOKE, BLOCK, method::EXPECT, [LENT + 1, 0, 0, 0]);
    let forbidden = call(BLOCK, block::LEND_FORBIDDEN, [0; 4]);
    write(b"  forbidden     ");
    match forbidden.args[0] {
        status::INSUFFICIENT_RIGHTS => {
            write(b"a service cannot pass on what it may only hold\n");
        }
        other => {
            write(b"handed anyway, or refused for the wrong reason: status ");
            write_number(other);
            write(b"\n");
        }
    }

    // And a writable mapping of it is refused: what was handed over is no
    // stronger than what the service held, which was read-only.
    let writable = syscall(
        syscall::INVOKE,
        LENT,
        method::ATTACH,
        [AT + 0x10000, 1, 0, 0],
    );
    write(b"  13 lent      ");
    match writable.status {
        status::INSUFFICIENT_RIGHTS => write(b"refused a writable mapping\n"),
        _ => write(b"WIDENED -- a copy stronger than the original\n"),
    }
}

/// Reads the lent page again, after the service has answered more requests.
///
/// The page was pinned when it was lent, and a pinned frame is never chosen
/// for eviction. If it had been chosen, this would be reading whatever block
/// took the frame — somebody else's data, silently, which is the failure this
/// step exists to prevent. The exhaustive form of this claim is on the host,
/// where every eviction can be checked; this is the same claim in a machine,
/// after real work.
fn held() {
    // SAFETY: the page the filesystem service lent, mapped read-only at this
    // address by `open`. If nothing was lent the read below would fault, which
    // is why the command is only useful after one.
    let head = unsafe { core::slice::from_raw_parts(LENT_AT as *const u8, 8) };
    write(b"  held          the lent page still begins \"");
    write(head);
    write(b"\"\n");
}

/// Gives back the page the filesystem service lent.
///
/// RFC 0016 left "what ends a lending?" open, and this is the answer: the
/// caller says it is done, and the service unpins the frame **and revokes what
/// it handed over**. Both halves matter — unpinning alone would leave this
/// program reading a frame the cache is free to fill with another file's block.
///
/// So what is checked here is not that the call succeeded. It is that the page
/// is *gone*: the capability no longer resolves, and mapping it again is
/// refused. Deliberately not checked by reading the address it used to be at,
/// which would fault — and since RFC 0017 step 1 a fault ends this domain,
/// which would end the shell and the test with it.
fn release() {
    let given = call(OPENED, dir::RELEASE, [0; 4]);
    write(b"  release       ");
    if given.status != status::OK || given.args[0] != dir::OK {
        write(b"the service would not take it back, status ");
        write_number(given.status);
        write(b"\n");
        return;
    }
    write(b"given back, ");
    write_number(given.args[1]);
    write(b" pages still lent\n");

    // And the capability is gone with it. Asked by trying to map it again:
    // a program that could still map what it has released could still read a
    // frame the service has reused.
    let again = syscall(
        syscall::INVOKE,
        LENT_PAGE,
        method::ATTACH,
        [LENT_AT + 0x20000, 0, 0, 0],
    );
    write(b"  released page ");
    match again.status {
        status::OK => write(b"MAPPED AGAIN -- the service did not take it back\n"),
        _ => write(b"can no longer be mapped\n"),
    }
}

/// One `dir` call against a held handle: declare where the answer's
/// capability may land, ask, and hand back the raw reply.
fn dir_call(held: u64, into: u64, method_number: u64, args: [u64; 4]) -> Reply {
    // Only the *destination* is cleared. The first version of this line
    // also deleted `held` -- the capability being invoked -- so the first
    // `pkg install` of a boot destroyed the shell's own /pkg handle and
    // every later `pkg` command found the slot empty. One character of
    // difference, and the whole command family died of it.
    let _ = syscall(syscall::INVOKE, into, method::DELETE, [0; 4]);
    let declared = syscall(syscall::INVOKE, held, method::EXPECT, [into, 0, 0, 0]);
    if declared.status != status::OK {
        return declared;
    }
    call(held, method_number, args)
}

/// The failure report every `pkg` refusal goes through: red, and saying
/// which step said no.
fn pkg_refused(step: &[u8], code: u64) {
    write(b"  [91mpkg: ");
    write(step);
    write(b" refused (");
    write_number(code);
    write(
        b")[0m
",
    );
}

/// Ensures the staging and transfer windows are mapped. Repeat attaches are
/// tolerated: the second `pkg` command of a session finds them where the
/// first put them.
fn pkg_attach() -> bool {
    let staged = syscall(
        syscall::INVOKE,
        STAGING,
        method::ATTACH,
        [STAGING_AT, 1, 0, 0],
    );
    let transfer = syscall(
        syscall::INVOKE,
        MEMORY_RW,
        method::ATTACH,
        [TRANSFER_AT, 1, 0, 0],
    );
    // `OK` the first time, and `SLOT_UNAVAILABLE` every time after -- the
    // range is already mapped, which is the kernel refusing to double-map,
    // not the window being absent. Both mean the window is there.
    let usable =
        |reply: &Reply| reply.status == status::OK || reply.status == status::SLOT_UNAVAILABLE;
    usable(&staged) && usable(&transfer)
}

/// Opens (or makes) the directory for one path component under `parent`,
/// leaving a writable handle at `into`. `EXISTS` falls back to opening,
/// which inherits writability from the parent.
fn pkg_ensure_directory(parent: u64, into: u64, name: &[u8]) -> bool {
    let (chunk, rest) = Chunk::take(name);
    if !rest.is_empty() {
        pkg_refused(b"a component name over sixteen bytes", 0);
        return false;
    }
    let made = dir_call(parent, into, dir::MAKE_DIRECTORY_AT, chunk.pack(0));
    if made.delivered() && made.raw() == dir::OK {
        return true;
    }
    if made.delivered() && made.raw() == dir::EXISTS {
        let opened = dir_call(parent, into, dir::OPEN_AT, chunk.pack(0));
        if opened.delivered() && opened.raw() == dir::OK {
            return true;
        }
        pkg_refused(b"opening an existing directory", opened.raw());
        return false;
    }
    pkg_refused(b"making a directory", made.raw());
    false
}

/// Writes `bytes` into the file whose writable handle sits at `handle`,
/// one transfer page at a time, and says how many crossed.
fn pkg_write_file(handle: u64, bytes: &[u8], writes: &mut u64) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let take = (bytes.len() - offset).min(4096);
        // SAFETY: the transfer window this program attached writable at
        // `TRANSFER_AT`, one page, and `take` is bounded to it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(offset),
                TRANSFER_AT as *mut u8,
                take,
            );
        }
        let wrote = call(
            handle,
            dir::WRITE_FROM,
            [MEMORY_RW, take as u64, offset as u64, 0],
        );
        if !wrote.delivered() || wrote.raw() != dir::OK {
            pkg_refused(b"writing", wrote.raw());
            return false;
        }
        *writes += 1;
        offset += take;
    }
    true
}

/// Creates and fills one file at `path` (at most two components) under the
/// package directory at `PKG_WORK`.
fn pkg_place_file(path: &[u8], bytes: &[u8], writes: &mut u64) -> bool {
    let mut parent = PKG_WORK;
    let mut name = path;
    if let Some(slash) = path.iter().position(|b| *b == b'/') {
        let (first, rest) = (&path[..slash], &path[slash + 1..]);
        if rest.contains(&b'/') {
            pkg_refused(b"a path deeper than two components", 0);
            return false;
        }
        if !pkg_ensure_directory(PKG_WORK, PKG_WORK2, first) {
            return false;
        }
        parent = PKG_WORK2;
        name = rest;
    }
    let (chunk, more) = Chunk::take(name);
    if !more.is_empty() {
        pkg_refused(b"a file name over sixteen bytes", 0);
        return false;
    }
    let made = dir_call(parent, PKG_FILE, dir::CREATE_AT, chunk.pack(0));
    if !made.delivered() || made.raw() != dir::OK {
        pkg_refused(b"creating a file", made.raw());
        return false;
    }
    let placed = pkg_write_file(PKG_FILE, bytes, writes);
    syscall(syscall::INVOKE, PKG_FILE, method::DELETE, [0; 4]);
    placed
}

/// `pkg install <file>`: reads a `.bpk` out of the boot image, verifies it
/// whole -- the same parser the build tools use, in ring 3 -- and installs
/// it under `/pkg`, payloads first and the manifest record last, so a crash
/// leaves droppings and never a lie.
fn pkg_install(file: &[u8]) {
    if !pkg_attach() {
        pkg_refused(b"mapping the staging memory", 0);
        return;
    }
    // The archive, out of the initrd through the filesystem service.
    let reset = call(FILESYSTEM, fs::RESET, [0; 4]);
    if !reset.delivered() {
        report_refusal(b"pkg", &reset);
        return;
    }
    if let Err(reply) = send_path(file) {
        report_refusal(b"pkg", &reply);
        return;
    }
    let opened = call(FILESYSTEM, fs::OPEN, [0; 4]);
    if !opened.delivered() || opened.outcome() != outcome::OK {
        write(
            b"  [91mpkg: no such package file[0m
",
        );
        return;
    }
    let loaded = call(FILESYSTEM, fs::READ_INTO, [STAGING, 16 * 4096, 0, 0]);
    if !loaded.delivered() || loaded.outcome() != outcome::OK {
        report_refusal(b"pkg: reading the archive", &loaded);
        return;
    }
    let size = loaded.value() as usize;
    // SAFETY: the staging window this program attached at `STAGING_AT`,
    // sixteen pages, and `size` is what the service wrote, bounded by the
    // limit it was given.
    let bytes =
        unsafe { core::slice::from_raw_parts(STAGING_AT as *const u8, size.min(16 * 4096)) };

    let verified = match bhaskix_pkg::package::verify(bytes) {
        Ok(verified) => verified,
        Err(_) => {
            write(
                b"  [91mpkg: not a package -- refused whole[0m
",
            );
            return;
        }
    };
    let manifest = verified.manifest();
    write(b"  verified   ");
    write(manifest.name);
    write(b" ");
    write(manifest.version);
    write(b" -- ");
    write_number(manifest.files().count() as u64);
    write(b" files, ");
    write_number(size as u64);
    write(
        b" bytes, digests good
",
    );

    // The package's own directory. EXISTS is "already installed", which is
    // an answer and not an error to bury.
    let (chunk, more) = Chunk::take(manifest.name);
    if !more.is_empty() {
        pkg_refused(b"a package name over sixteen bytes", 0);
        return;
    }
    let made = dir_call(PKG_DIR, PKG_WORK, dir::MAKE_DIRECTORY_AT, chunk.pack(0));
    if made.delivered() && made.raw() == dir::EXISTS {
        write(
            b"  [93mpkg: already installed -- 'pkg remove' it first[0m
",
        );
        return;
    }
    if !made.delivered() || made.raw() != dir::OK {
        pkg_refused(b"making the package directory", made.raw());
        return;
    }

    // Payloads first... priced from here: the verify above is arithmetic,
    // and what the journal charges for is what follows.
    let begun = cycles();
    let mut writes = 0u64;
    let mut payload_bytes = 0u64;
    let mut placed = true;
    for file_entry in manifest.files() {
        let Some(data) = verified.data(file_entry.path) else {
            placed = false;
            break;
        };
        payload_bytes += data.len() as u64;
        if !pkg_place_file(file_entry.path, data, &mut writes) {
            placed = false;
            break;
        }
    }
    // ...the record last. Only after every payload landed does anything
    // claim the install happened.
    if placed {
        let (chunk, _) = Chunk::take(b"manifest");
        let made = dir_call(PKG_WORK, PKG_FILE, dir::CREATE_AT, chunk.pack(0));
        placed = made.delivered()
            && made.raw() == dir::OK
            && pkg_write_file(PKG_FILE, verified.manifest_bytes(), &mut writes);
        syscall(syscall::INVOKE, PKG_FILE, method::DELETE, [0; 4]);
    }
    syscall(syscall::INVOKE, PKG_WORK2, method::DELETE, [0; 4]);
    syscall(syscall::INVOKE, PKG_WORK, method::DELETE, [0; 4]);
    if placed {
        write(b"  [1;32minstalled[0m  /pkg/");
        write(manifest.name);
        write(b" -- ");
        write_number(payload_bytes);
        write(b" payload bytes through the journal in ");
        write_number(writes);
        write(b" writes, ");
        write_number(cycles().wrapping_sub(begun));
        write(b" cycles\n");
    } else {
        write(
            b"  [91mpkg: the install did not finish -- no record was written[0m
",
        );
    }
}

/// `pkg list`: what is installed, one line each.
fn pkg_list() {
    let mut index = 0u64;
    let mut count = 0u64;
    loop {
        let reply = call(PKG_DIR, dir::LIST_AT, [index, 0, 0, 0]);
        if !reply.delivered() {
            report_refusal(b"pkg list", &reply);
            return;
        }
        match reply.args[0] {
            dir::OK => {
                let length = dir::listing_length(reply.args[3]);
                let mut name = [0u8; 16];
                name[..8].copy_from_slice(&reply.args[1].to_le_bytes());
                name[8..].copy_from_slice(&reply.args[2].to_le_bytes());
                write(b"  [1;32m");
                write(&name[..length.min(16)]);
                write(
                    b"[0m
",
                );
                count += 1;
            }
            dir::END => break,
            other => {
                pkg_refused(b"listing", other);
                return;
            }
        }
        index += 1;
    }
    write(b"  ");
    write_number(count);
    write(
        b" installed
",
    );
}

/// Removes every file entry of the directory held at `held`, restarting at
/// index zero after each removal. Directories under it are cleared one
/// level down -- the install refused anything deeper.
fn pkg_clear_directory(held: u64, spare: u64) -> bool {
    loop {
        let reply = call(held, dir::LIST_AT, [0, 0, 0, 0]);
        if !reply.delivered() {
            return false;
        }
        match reply.args[0] {
            dir::END => return true,
            dir::OK => {}
            _ => return false,
        }
        // **Through the accessors, and this is the site that made them
        // necessary.** The kind used to be read here as `args[3] >> 8`,
        // which was right while the word held nothing above it; the listing
        // now carries an inode there, and the hand-written test would call
        // every file a directory and send this loop recursing into them.
        let length = dir::listing_length(reply.args[3]);
        let is_directory = dir::listing_is_directory(reply.args[3]);
        let mut name = [0u8; 16];
        name[..8].copy_from_slice(&reply.args[1].to_le_bytes());
        name[8..].copy_from_slice(&reply.args[2].to_le_bytes());
        let (chunk, _) = Chunk::take(&name[..length.min(16)]);
        if is_directory {
            if spare == 0 {
                // Two levels was the install's stated ceiling; finding a
                // third here means the tree was not this program's work.
                return false;
            }
            let opened = dir_call(held, spare, dir::OPEN_AT, chunk.pack(0));
            if !opened.delivered() || opened.raw() != dir::OK {
                return false;
            }
            if !pkg_clear_directory(spare, 0) {
                return false;
            }
            syscall(syscall::INVOKE, spare, method::DELETE, [0; 4]);
        }
        let removed = call(held, dir::REMOVE_AT, chunk.pack(0));
        if !removed.delivered() || removed.raw() != dir::OK {
            return false;
        }
    }
}

/// `pkg remove <name>`: the record first, the payload after -- a torn
/// remove leaves droppings and no claim of presence.
fn pkg_remove(name: &[u8]) {
    let (chunk, more) = Chunk::take(name);
    if !more.is_empty() {
        pkg_refused(b"a package name over sixteen bytes", 0);
        return;
    }
    let opened = dir_call(PKG_DIR, PKG_WORK, dir::OPEN_AT, chunk.pack(0));
    if opened.delivered() && opened.raw() == dir::NO_SUCH_NAME {
        write(
            b"  [93mpkg: not installed[0m
",
        );
        return;
    }
    if !opened.delivered() || opened.raw() != dir::OK {
        pkg_refused(b"opening the package", opened.raw());
        return;
    }
    // The record goes first: from here on the package does not claim to be
    // installed, whatever else survives a crash.
    let begun = cycles();
    let (record, _) = Chunk::take(b"manifest");
    let _ = call(PKG_WORK, dir::REMOVE_AT, record.pack(0));
    let cleared = pkg_clear_directory(PKG_WORK, PKG_WORK2);
    syscall(syscall::INVOKE, PKG_WORK2, method::DELETE, [0; 4]);
    syscall(syscall::INVOKE, PKG_WORK, method::DELETE, [0; 4]);
    if !cleared {
        write(
            b"  [91mpkg: droppings remain -- the record is gone, run remove again[0m
",
        );
        return;
    }
    let removed = call(PKG_DIR, dir::REMOVE_AT, chunk.pack(0));
    if !removed.delivered() || removed.raw() != dir::OK {
        pkg_refused(b"removing the package directory", removed.raw());
        return;
    }
    write(b"  [1;32mremoved[0m    ");
    write(name);
    write(b" -- ");
    write_number(cycles().wrapping_sub(begun));
    write(b" cycles through the journal\n");
}

/// The cycle counter, for pricing `pkg` operations. Raw cycles on
/// purpose: this program was not told the rate (the boot log's feature
/// lines carry it for whoever converts), and a number with honest units
/// beats a guessed millisecond.
fn cycles() -> u64 {
    let low: u64;
    let high: u64;
    // SAFETY: `rdtsc` reads a counter and writes two registers, both
    // listed; it is unprivileged on this machine by design (RFC 0019:
    // reading time is ambient, being woken is the scarce thing).
    unsafe {
        core::arch::asm!("rdtsc", out("rax") low, out("rdx") high, options(nomem, nostack));
    }
    (high << 32) | low
}

// A package-run child's console carries `BADGE_CONSOLE`, the same badge
// `spawn` grants: the shell's console capability is itself badged, and a
// grant may narrow rights but never swap identities — a fresh badge here
// was refused with INSUFFICIENT_RIGHTS, which is the monotonicity rule
// doing its job against this very program.

/// Reads the whole file whose handle sits at `handle` into the memory
/// object at `slot`, one transfer page per call, reassembled in place.
/// Returns the byte count, or `None` with the refusal reported.
fn pkg_read_file(handle: u64, slot: u64, limit: u64) -> Option<u64> {
    let mut offset = 0u64;
    loop {
        let reply = call(handle, dir::READ_INTO, [slot, 4096, offset, 0]);
        if !reply.delivered() || reply.raw() != dir::OK {
            pkg_refused(b"reading an installed file", reply.raw());
            return None;
        }
        let read = reply.args[1];
        if read == 0 {
            return Some(offset);
        }
        offset += read;
        if offset > limit {
            pkg_refused(b"a file bigger than the staging memory", 0);
            return None;
        }
    }
}

/// `pkg run <name>`: starts an installed program with **exactly the grants
/// its manifest requested and this shell holds** — RFC 0030 step 4. An
/// over-ask is refused whole, before any domain exists: no partial grants,
/// no silently narrowed authority, the same rule the driver enumerator and
/// RFC 0022 enforce.
fn pkg_run(name: &[u8]) {
    if !pkg_attach() {
        pkg_refused(b"mapping the staging memory", 0);
        return;
    }
    let (chunk, more) = Chunk::take(name);
    if !more.is_empty() {
        pkg_refused(b"a package name over sixteen bytes", 0);
        return;
    }
    let opened = dir_call(PKG_DIR, PKG_WORK, dir::OPEN_AT, chunk.pack(0));
    if opened.delivered() && opened.raw() == dir::NO_SUCH_NAME {
        write(b"  \x1b[93mpkg: not installed\x1b[0m\n");
        return;
    }
    if !opened.delivered() || opened.raw() != dir::OK {
        pkg_refused(b"opening the package", opened.raw());
        return;
    }

    // The record, read back and parsed with the same grammar that admitted
    // it at install. The authority about to be granted is the authority
    // that was reviewed -- this file, not a memory of it.
    let (record, _) = Chunk::take(b"manifest");
    let record_handle = dir_call(PKG_WORK, PKG_FILE, dir::OPEN_AT, record.pack(0));
    if !record_handle.delivered() || record_handle.raw() != dir::OK {
        pkg_refused(b"opening the record", record_handle.raw());
        return;
    }
    let Some(record_bytes) = pkg_read_file(PKG_FILE, STAGING, 4096) else {
        return;
    };
    // SAFETY: the staging window this program attached at `STAGING_AT`;
    // the record was just read into its first `record_bytes` bytes.
    let record_slice =
        unsafe { core::slice::from_raw_parts(STAGING_AT as *const u8, record_bytes as usize) };
    let Ok(manifest) = bhaskix_pkg::manifest::parse(record_slice) else {
        write(b"  \x1b[91mpkg: the installed record does not parse (");
        write_number(record_bytes);
        write(b" bytes) -- refusing to run\x1b[0m\n");
        return;
    };
    let Some(program) = manifest.programs().next() else {
        write(b"  \x1b[93mpkg: this package carries no program\x1b[0m\n");
        return;
    };

    // Every request checked against what this shell can grant, before any
    // domain exists. The vocabulary this spawner can honour is exactly one
    // word today -- console -- and anything else is refused whole, by name.
    let mut grantable = true;
    for cap in program.caps() {
        if !matches!(cap, bhaskix_pkg::manifest::Cap::Console) {
            grantable = false;
        }
    }
    if !grantable {
        write(
            b"  \x1b[91mpkg: the manifest asks for authority this shell does not hold -- \
refused whole, nothing granted\x1b[0m\n",
        );
        return;
    }

    // The program's bytes, out of the installed tree into the staging
    // object -- overwriting the record copy, which has served its purpose.
    let mut parent = PKG_WORK;
    let mut file_name = program.path;
    if let Some(slash) = program.path.iter().position(|b| *b == b'/') {
        let (first, rest) = (&program.path[..slash], &program.path[slash + 1..]);
        let (dir_chunk, _) = Chunk::take(first);
        let inner = dir_call(PKG_WORK, PKG_WORK2, dir::OPEN_AT, dir_chunk.pack(0));
        if !inner.delivered() || inner.raw() != dir::OK {
            pkg_refused(b"opening the program's directory", inner.raw());
            return;
        }
        parent = PKG_WORK2;
        file_name = rest;
    }
    let (file_chunk, _) = Chunk::take(file_name);
    let binary = dir_call(parent, PKG_FILE, dir::OPEN_AT, file_chunk.pack(0));
    if !binary.delivered() || binary.raw() != dir::OK {
        pkg_refused(b"opening the program", binary.raw());
        return;
    }
    let Some(bytes) = pkg_read_file(PKG_FILE, STAGING, 16 * 4096) else {
        return;
    };
    syscall(syscall::INVOKE, PKG_FILE, method::DELETE, [0; 4]);
    syscall(syscall::INVOKE, PKG_WORK2, method::DELETE, [0; 4]);
    syscall(syscall::INVOKE, PKG_WORK, method::DELETE, [0; 4]);

    // From here it is `spawn`'s own arc: an empty domain, the reviewed
    // grants, the ending bound before the start. The entry argument is
    // zero -- the manifest declares `entry hertz` and this spawner cannot
    // know the rate; the first installed program that keeps time is the
    // trigger for threading it through, and `bin/hello` ignores it.
    let made = syscall(
        syscall::INVOKE,
        DOMAIN_CONTROL,
        method::SPAWN,
        [CHILD, NAME_LOW, NAME_HIGH, 0],
    );
    if !made.delivered() {
        report_refusal(b"pkg run: creating the domain", &made);
        return;
    }
    for cap in program.caps() {
        let bhaskix_pkg::manifest::Cap::Console = cap else {
            continue;
        };
        let granted = syscall(
            syscall::INVOKE,
            CHILD,
            method::GRANT,
            [CONSOLE, 0, EVERYTHING_HELD, BADGE_CONSOLE],
        );
        if !granted.delivered() {
            report_refusal(b"pkg run: granting the console", &granted);
            let _ = syscall(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
            return;
        }
    }
    let bound = syscall(
        syscall::INVOKE,
        CHILD,
        method::BIND,
        [SIGNAL, CHILD_BADGE, 0, 0],
    );
    if !bound.delivered() {
        report_refusal(b"pkg run: asking to be told it ended", &bound);
        let _ = syscall(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
        return;
    }
    write(b"  \x1b[1;32mrunning\x1b[0m    ");
    write(name);
    write(b" (");
    write_number(bytes);
    write(b" bytes, grants from its manifest)\n");
    let started = syscall(
        syscall::INVOKE,
        CHILD,
        method::START,
        [STAGING, bytes, 0, 0],
    );
    if !started.delivered() {
        report_refusal(b"pkg run: starting it", &started);
        let _ = syscall(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
        return;
    }
    let ended = syscall(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
    if ended.delivered() {
        write(b"  it ended cleanly\n");
    }
    let _ = syscall(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
}

/// The `pkg` family -- install, list, remove. RFC 0030 steps 3 and 5,
/// and the shell is the actor because it already holds exactly the
/// authority installing needs: the boot image read-only, `/pkg` writable,
/// and nothing else.
fn pkg(rest: &[u8]) {
    let (word, name) = split(rest);
    match word {
        b"install" if !name.is_empty() => pkg_install(name),
        b"list" => pkg_list(),
        b"run" if !name.is_empty() => pkg_run(name),
        b"remove" if !name.is_empty() => pkg_remove(name),
        _ => {
            write(
                b"  pkg install <file> | pkg list | pkg run <name> | pkg remove <name>
",
            );
        }
    }
}

fn run(line: &[u8]) {
    let (command, rest) = split(line);
    match command {
        b"" => {}
        b"help" => help(),
        b"dmesg" => dmesg(),
        b"echo" => {
            write(rest);
            write(b"\n");
        }
        b"ls" => list(rest),
        b"ask" => ask(),
        b"held" => held(),
        b"release" => release(),
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
        b"net" => network(rest),
        b"pkg" => pkg(rest),
        b"cat" => {
            if rest.is_empty() {
                write(b"  cat: which file?\n");
            } else {
                cat(rest);
            }
        }
        b"spawn" => {
            if rest.is_empty() {
                write(b"  spawn: which program?\n");
            } else {
                spawn(rest);
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
