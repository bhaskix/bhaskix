// SPDX-License-Identifier: Apache-2.0
//! A kernel shell.
//!
//! `docs/roadmap.md` M6 asks for "a kernel shell, then a user-mode shell over
//! the syscall interface". This is the first of those, and the distinction
//! matters: **this shell is the kernel**. It runs in ring 0, calls kernel
//! functions directly, and holds no capability, because a thread inside the
//! kernel is not subject to the mechanism that would ask for one.
//!
//! That makes it an operator's tool and a debugging aid, not a security
//! boundary and not a product. M6-05's user-mode shell is the one that has to
//! ask for everything it does; the difference between the two is the whole
//! point of the exercise, and this one exists partly to make that visible.
//!
//! # What it deliberately cannot do
//!
//! No command writes anything: no `rm`, no `mkfs`, no `poke`. A kernel shell
//! with a memory-writing command is a debugging tool that can also silently
//! corrupt the system it is meant to explain, and every session with it is
//! afterwards suspect. Reading is enough to answer the questions this shell
//! exists to answer.
//!
//! # Structure
//!
//! [`run`] takes a line and executes it, with no reference to where the line
//! came from. That is what lets the boot self-test run commands with no
//! console input at all, and lets the line editing and the input path be
//! tested separately from what commands do.

use crate::input::{Edit, LineEditor};
use crate::{elf, frames, print, println, sched, ustar, vfs};

/// Tokens one command line may have.
///
/// Bounded because parsing must not allocate: the shell runs on a kernel
/// thread with a fixed stack, and a line arrives one byte at a time from an
/// interrupt.
const MAX_ARGUMENTS: usize = 8;

/// What happened to a line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// The line held no command.
    Empty,
    /// The command ran.
    Ran,
    /// No command by that name.
    Unknown,
    /// The command ran and reported a problem.
    Failed,
}

/// Splits a line into whitespace-separated tokens.
///
/// No quoting, no escapes, no globbing. Each of those is a parser, and a
/// parser in a shell is a place for a line to mean something other than what
/// it looks like. When a command needs an argument with a space in it, that is
/// the moment to design quoting, not before.
fn tokenise<'a>(line: &'a [u8], tokens: &mut [&'a [u8]; MAX_ARGUMENTS]) -> usize {
    let mut count = 0;
    let mut start = None;

    for index in 0..=line.len() {
        let space = index == line.len() || line[index].is_ascii_whitespace();
        match (space, start) {
            (false, None) => start = Some(index),
            (true, Some(first)) => {
                if count == MAX_ARGUMENTS {
                    return count;
                }
                tokens[count] = &line[first..index];
                count += 1;
                start = None;
            }
            _ => {}
        }
    }
    count
}

/// Runs one command line.
///
/// Separate from the reading loop so the boot self-test can exercise every
/// command without a console, an interrupt, or anyone typing. A shell whose
/// commands can only be run by hand is a shell whose commands are tested by
/// hand.
pub fn run(line: &[u8]) -> Outcome {
    let mut tokens: [&[u8]; MAX_ARGUMENTS] = [b""; MAX_ARGUMENTS];
    let count = tokenise(line, &mut tokens);
    if count == 0 {
        return Outcome::Empty;
    }

    let arguments = &tokens[1..count];
    match tokens[0] {
        b"help" => help(),
        b"echo" => echo(arguments),
        b"ls" => list(arguments),
        b"cat" => concatenate(arguments),
        b"readelf" => describe_elf(arguments),
        b"free" => memory(),
        b"ps" => threads(),
        b"uptime" => uptime(),
        b"input" => input_statistics(),
        b"lsblk" => disk(),
        unknown => {
            println!("{}: not a command. Try 'help'.", Text(unknown));
            Outcome::Unknown
        }
    }
}

/// Prints a *name* — a path, a command, an argument.
///
/// A wrapper rather than `from_utf8`, because a name in this kernel is bytes
/// and need not be text. Anything but printable ASCII becomes `?`, newlines
/// and tabs included: a console that echoed whatever arrived would let a
/// crafted filename move the cursor, clear the screen, or print a line that
/// looks like it came from the kernel.
struct Text<'a>(&'a [u8]);

/// Prints file *contents*.
///
/// The same substitution, except that newline and tab pass through — a text
/// file is unreadable without them. The distinction from [`Text`] is
/// deliberate: contents are expected to contain layout, names are not, and a
/// name that could contain a newline could fake a line of output.
struct Body<'a>(&'a [u8]);

fn write_filtered(
    f: &mut core::fmt::Formatter<'_>,
    bytes: &[u8],
    layout: bool,
) -> core::fmt::Result {
    for byte in bytes {
        let character = match byte {
            b if b.is_ascii_graphic() || *b == b' ' => *byte as char,
            b'\n' | b'\t' if layout => *byte as char,
            _ => '?',
        };
        core::fmt::Write::write_char(f, character)?;
    }
    Ok(())
}

impl core::fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_filtered(f, self.0, false)
    }
}

impl core::fmt::Display for Body<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_filtered(f, self.0, true)
    }
}

fn help() -> Outcome {
    // **The names a Linux user would guess**, which is the standing rule for
    // every surface here: `readelf`, `free` and `lsblk` were `elf`, `mem` and
    // `disk` until 2026-08-26. Each has an exact analogue rather than an
    // approximate one, which is why these three moved and the capability
    // commands in the user-mode shell did not -- `map` there is not `pmap`,
    // and calling it that would describe something this system does not do.
    //
    // `ps` was already named this way, and shows *threads*: the closest Linux
    // gets is `ps -T`, and the line says "by cpu" rather than pretending
    // otherwise.
    println!("  commands");
    println!("    help              this list");
    println!("    echo <words>      print the arguments");
    println!("    ls [path]         list a directory in the initrd");
    println!("    cat <path>        print a file");
    println!("    readelf <path>    what the ELF loader makes of a file");
    println!("    free              physical memory and the kernel heap");
    println!("    ps                threads, by cpu");
    println!("    uptime            time since the kernel started");
    println!("    input             console input statistics");
    println!("    lsblk             the block device, if there is one");
    println!();
    println!("  this shell is the kernel: it holds no capability and asks");
    println!("  permission for nothing. m6-05's user-mode shell will.");
    Outcome::Ran
}

fn echo(arguments: &[&[u8]]) -> Outcome {
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            print!(" ");
        }
        print!("{}", Text(argument));
    }
    println!();
    Outcome::Ran
}

fn list(arguments: &[&[u8]]) -> Outcome {
    let path = arguments.first().copied().unwrap_or(b"");
    let mut entries = 0;

    vfs::list(path, |name, kind, size| {
        entries += 1;
        let mark = match kind {
            ustar::EntryKind::Directory => "/",
            _ => "",
        };
        println!("  {:>8}  {}{}", size, Text(name), mark);
    });

    if entries == 0 {
        // Not an error: an empty directory and a missing one look the same
        // through a listing, and saying which would be a claim this layer
        // cannot support. `cat` will say if the name is not there.
        println!("  nothing under {}", Text(path));
    }
    Outcome::Ran
}

fn concatenate(arguments: &[&[u8]]) -> Outcome {
    let Some(path) = arguments.first() else {
        println!("  cat: which file?");
        return Outcome::Failed;
    };

    let mut file = match vfs::open(path) {
        Ok(file) => file,
        Err(error) => {
            println!("  cat: {}: {}", Text(path), reason(error));
            return Outcome::Failed;
        }
    };

    // Through the cursor, in chunks, rather than by taking the whole slice.
    // The slice is available and this is the shape a real file needs -- when
    // the backing is a disk, `bytes()` will not exist and this loop will.
    let mut buffer = [0u8; 64];
    let mut last = b'\n';
    loop {
        let read = file.read(&mut buffer);
        if read == 0 {
            break;
        }
        last = buffer[read - 1];
        print!("{}", Body(&buffer[..read]));
    }
    // A newline only if the file did not end with one. Adding one regardless
    // puts a blank line after every text file; adding none leaves the prompt
    // in the middle of the last line of a file that lacks one.
    if last != b'\n' {
        println!();
    }
    Outcome::Ran
}

fn reason(error: vfs::VfsError) -> &'static str {
    match error {
        vfs::VfsError::NotMounted => "no filesystem",
        vfs::VfsError::NotFound => "no such file",
        vfs::VfsError::BadPath => "not a path this filesystem will resolve",
        vfs::VfsError::NotAFile => "not a file",
    }
}

fn describe_elf(arguments: &[&[u8]]) -> Outcome {
    let Some(path) = arguments.first() else {
        println!("  elf: which file?");
        return Outcome::Failed;
    };

    let file = match vfs::open(path) {
        Ok(file) => file,
        Err(error) => {
            println!("  elf: {}: {}", Text(path), reason(error));
            return Outcome::Failed;
        }
    };

    match elf::parse(file.bytes()) {
        Ok(image) => {
            println!(
                "  entry {:#x}, {} segments",
                image.entry,
                image.segment_count()
            );
            for segment in image.segments() {
                println!(
                    "    {:#012x}  {:>7} bytes in memory, {:>7} in file  {}",
                    segment.address, segment.memory_size, segment.file_size, segment.protection
                );
            }
            Outcome::Ran
        }
        Err(error) => {
            // The specific refusal, not "invalid". Which check rejected a file
            // is the entire content of the answer.
            println!("  elf: {}: refused, {:?}", Text(path), error);
            Outcome::Failed
        }
    }
}

fn memory() -> Outcome {
    let free = crate::heap::free_frames();
    let available = crate::heap::available_frames();
    println!(
        "  frames  {free} free ({} MiB), {available} available including per-cpu reserves",
        free * 4096 / (1024 * 1024)
    );
    println!(
        "  reserve {} frames held, {} refills, {} hits, {} misses",
        frames::held(),
        frames::refilled(),
        frames::hits(),
        frames::misses()
    );
    Outcome::Ran
}

fn threads() -> Outcome {
    println!("   cpu   id  state     class     runs  moves  name");
    sched::for_each(|cpu, id, name, state, runs, migrations, class| {
        println!("  {cpu:>4}  {id:>3}  {state:<8}  {class:<8}  {runs:>4}  {migrations:>5}  {name}");
    });
    Outcome::Ran
}

fn uptime() -> Outcome {
    match crate::time::now_nanos() {
        Some(nanos) => println!(
            "  up {}.{:03} seconds, {} timer ticks",
            nanos / 1_000_000_000,
            nanos % 1_000_000_000 / 1_000_000,
            crate::trap::ticks()
        ),
        // Without a calibrated TSC there is no seconds figure to give, and
        // inventing one from the tick count would be a number that looks
        // authoritative and drifts.
        None => println!(
            "  {} timer ticks; no calibrated clock to convert them",
            crate::trap::ticks()
        ),
    }
    Outcome::Ran
}

fn disk() -> Outcome {
    let Some((bus, device, function)) = crate::virtio::location() else {
        println!("  no block device");
        return Outcome::Ran;
    };
    let capacity = crate::virtio::capacity();
    let (completed, timeouts) = crate::virtio::statistics();
    println!(
        "  virtio-blk at {bus:02x}:{device:02x}.{function}, {capacity} sectors ({} KiB)",
        capacity * crate::virtio::SECTOR / 1024
    );
    println!(
        "  status {:#04x}, {completed} requests completed, {timeouts} timed out",
        crate::virtio::status()
    );

    // Read the first sector and say what it holds. A driver that is only ever
    // exercised at boot is one whose failures are only ever seen at boot.
    let mut sector = [0u8; 512];
    match crate::virtio::read(0, &mut sector) {
        Ok(()) => {
            let name = ustar::Archive::new(&sector)
                .next()
                .map(|entry| entry.name().len())
                .unwrap_or(0);
            if name > 0 {
                println!("  sector 0 is a ustar header");
            } else {
                println!("  sector 0 read, and is not a ustar header");
            }
            Outcome::Ran
        }
        Err(error) => {
            println!("  reading sector 0 failed: {error:?}");
            Outcome::Failed
        }
    }
}

fn input_statistics() -> Outcome {
    let (received, dropped, interrupts) = crate::input::statistics();
    println!("  {received} bytes in {interrupts} interrupts, {dropped} dropped");
    // **Broken out, because the total cannot say whether the keyboard works.**
    // A machine whose keys do nothing needs to know which half is silent, and
    // the scancode count is a third thing again: a key release and a modifier
    // are scancodes that emit no byte, so scancodes without bytes means the
    // i8042 is delivering and the decoder is swallowing.
    let (serial, serial_lost, keys, keys_lost) = crate::input::per_source();
    let scancodes = crate::keyboard::scancodes();
    println!(
        "  serial {serial} ({serial_lost} dropped), keyboard {keys} from {scancodes} scancodes \
         ({keys_lost} dropped)"
    );
    Outcome::Ran
}

/// The prompt.
const PROMPT: &str = "bhaskix> ";

/// Reads and runs command lines, for ever.
///
/// Never returns: it is the thread's whole life. Entered with the console
/// input path already installed and this thread pinned to the CPU the serial
/// interrupt is routed to — see `input`'s module header for why that pairing
/// is load-bearing rather than incidental.
pub extern "C" fn main(_argument: u64) -> ! {
    let mut editor = LineEditor::new();

    println!();
    println!("  a shell. 'help' lists what it can do.");
    print!("{PROMPT}");

    loop {
        let byte = crate::input::read();
        match editor.accept(byte) {
            Edit::Inserted(byte) => print!("{}", byte as char),
            // Back over the character, write a space where it was, back again.
            // The three steps are what a terminal needs to actually erase;
            // a lone backspace only moves the cursor, leaving the character
            // on screen and the operator looking at a line that is not theirs.
            Edit::Erased => print!("\u{8} \u{8}"),
            Edit::Cancelled => {
                println!("^C");
                print!("{PROMPT}");
            }
            Edit::Complete => {
                println!();
                run(editor.line());
                editor.clear();
                print!("{PROMPT}");
            }
            Edit::Ignored => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens_of<'a>(line: &'a [u8], storage: &mut [&'a [u8]; MAX_ARGUMENTS]) -> usize {
        tokenise(line, storage)
    }

    #[test]
    fn a_line_splits_on_runs_of_whitespace() {
        let mut tokens = [b"".as_slice(); MAX_ARGUMENTS];
        let count = tokens_of(b"  cat   etc/hostname \t ", &mut tokens);
        assert_eq!(count, 2);
        assert_eq!(tokens[0], b"cat");
        assert_eq!(tokens[1], b"etc/hostname");
    }

    #[test]
    fn an_empty_line_has_no_tokens_and_runs_nothing() {
        let mut tokens = [b"".as_slice(); MAX_ARGUMENTS];
        assert_eq!(tokens_of(b"", &mut tokens), 0);
        assert_eq!(tokens_of(b"   \t  ", &mut tokens), 0);
        assert_eq!(run(b"   "), Outcome::Empty);
    }

    #[test]
    fn more_arguments_than_there_is_room_for_are_dropped_not_overflowed() {
        let mut tokens = [b"".as_slice(); MAX_ARGUMENTS];
        let count = tokens_of(b"a b c d e f g h i j k l", &mut tokens);
        assert_eq!(count, MAX_ARGUMENTS);
        assert_eq!(tokens[MAX_ARGUMENTS - 1], b"h");
    }

    #[test]
    fn an_unknown_command_says_so_rather_than_doing_nothing() {
        // A shell that silently ignores a typo is one where a mistyped command
        // and a command that did nothing look identical.
        assert_eq!(run(b"nosuchthing"), Outcome::Unknown);
    }

    #[test]
    fn unprintable_bytes_in_a_name_are_not_sent_to_the_terminal() {
        // A crafted filename must not be able to move the cursor, clear the
        // screen, or hide the line after it. `?` is not prettier -- it is the
        // difference between printing a name and executing it.
        extern crate alloc;
        use alloc::format;

        assert_eq!(format!("{}", Text(b"hello.txt")), "hello.txt");
        assert_eq!(format!("{}", Text(b"a\x1b[2Jb")), "a?[2Jb");
        assert_eq!(format!("{}", Text(b"\x07\r\n")), "???");

        // Contents keep their layout; names do not get to have any.
        assert_eq!(format!("{}", Body(b"one\ntwo\n")), "one\ntwo\n");
        assert_eq!(format!("{}", Text(b"one\ntwo\n")), "one?two?");
        assert_eq!(format!("{}", Body(b"\x1b[2J")), "?[2J");
    }
}
