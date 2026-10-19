// SPDX-License-Identifier: Apache-2.0
//! The console service: bytes out, bytes in, and no state of its own.
//!
//! The first service to live outside the kernel crate. Nothing here can name a
//! kernel type, so everything it does to the machine goes through [`Ports`] —
//! which makes this file the shortest honest answer to "what does the console
//! actually need?". It needs to put a character somewhere and to take a byte
//! from somewhere. That is all, and it took moving it out of the kernel to be
//! able to say so.
#![no_std]

use bhaskix_abi::{CHUNK_BYTES, Chunk, console, outcome, with_outcome};
use bhaskix_service::{Reply, Request, Service, StartError};

/// What the console reaches for, and the whole of it.
///
/// Function pointers rather than a trait, because a trait object needs a
/// vtable in memory both placements agree on and a generic parameter would
/// spread through every caller for no gain. These are supplied by the
/// placement: in the nucleus they are the kernel's own routines, and in a
/// domain they are calls out to a driver.
#[derive(Clone, Copy)]
pub struct Ports {
    /// Puts one character on the machine's console.
    pub put: fn(char),
    /// Puts a run of already-filtered bytes with the console held once.
    ///
    /// RFC 0050 gave the nucleus `PUT_RUN` and only the Linux adapter used it,
    /// so a *native* program's line could still arrive in pieces — `bin/sup`'s
    /// `sup: starting ch` has been seen with a kernel report inside it. Every
    /// caller of this service now goes through one invocation per chunk instead
    /// of one per byte.
    ///
    /// **Already filtered**, and that is the caller's job rather than this
    /// port's: a held line goes through `sanitize`, which passes colour and
    /// nothing else, and a caller with no held line through the strict
    /// substitution -- so a program still cannot clear the screen, move the
    /// cursor, or blink, hide or reverse text on the kernel's console.
    pub put_run: fn(&[u8]),
    /// Waits for a byte to be typed, and returns it.
    pub read: fn() -> u8,
    /// Takes a byte if one is already waiting, without blocking.
    pub try_read: fn() -> Option<u8>,
    /// How many bytes of what the kernel printed are kept. RFC 0042.
    pub record_size: fn() -> usize,
    /// Eight bytes of that record from `offset`, zero-padded past the end.
    ///
    /// Eight and not sixteen because that is what one reply word carries in the
    /// domain placement, and the placement is what this abstraction exists to
    /// hide. The service asks twice per chunk.
    pub record_at: fn(usize) -> [u8; 8],
    /// One packed pair of input counters, chosen by the selector — RFC 0051.
    ///
    /// The nucleus answers one word per call because a system call returns one;
    /// this service asks three times and hands all three back in a single reply,
    /// which is the same shape `record_at` uses and for the same reason. The
    /// selector and the packing are `bhaskix_abi::method::INPUT_STATS`'s.
    pub input_stats: fn(u64) -> u64,
}

// There is deliberately no counter here.
//
// An earlier version had one, and the service called it. That works in the
// nucleus, where the service is inside the thing keeping the number, and not
// in a domain, where it would have to be a fourth system call whose only
// purpose is bookkeeping — or a number the boot report cannot see. The three
// above are all done *by* the placement, so the placement counts them, and the
// count means the same thing wherever the service runs.

/// How much of one caller's line is held before it goes out regardless.
///
/// `MAX_CONSOLE_RUN`, so a flush is always a single `PUT_RUN` and never two.
const LINE_BYTES: usize = 256;

/// How many callers can have a partial line held at once.
///
/// Four, and a fifth writes straight through — RFC 0052. Falling back to
/// unbuffered is the same behaviour this service had before the discipline
/// existed, which makes the overflow case degraded rather than broken.
const LINE_HOLDERS: usize = 4;

/// One caller's partial line.
#[derive(Clone, Copy)]
struct Line {
    /// The badge that owns it. Zero means free: a badge of zero is refused
    /// everywhere in this system, so it cannot collide with a real caller.
    badge: u64,
    used: usize,
    bytes: [u8; LINE_BYTES],
}

/// Partial lines, one per caller — RFC 0052.
///
/// **Keyed by badge, and that is the whole of why this is safe.** The kernel
/// stamps `Request::badge` from the capability the caller used and the caller
/// cannot choose it, so two domains writing at once cannot be spliced into each
/// other's lines — which would be a worse fault than the one being fixed.
pub struct Lines {
    held: [Line; LINE_HOLDERS],
}

impl Lines {
    const fn new() -> Self {
        Self {
            held: [Line {
                badge: 0,
                used: 0,
                bytes: [0; LINE_BYTES],
            }; LINE_HOLDERS],
        }
    }

    /// The slot for `badge`, claiming a free one if it has none.
    ///
    /// `None` when every slot belongs to somebody else — the fifth caller,
    /// which writes straight through.
    fn slot(&mut self, badge: u64) -> Option<&mut Line> {
        let existing = self.held.iter().position(|line| line.badge == badge);
        let index = match existing {
            Some(index) => index,
            None => {
                let free = self.held.iter().position(|line| line.badge == 0)?;
                self.held[free].badge = badge;
                self.held[free].used = 0;
                free
            }
        };
        self.held.get_mut(index)
    }

    /// Puts everything held for `badge`, if anything is.
    fn flush(&mut self, ports: &Ports, badge: u64) {
        let Some(index) = self.held.iter().position(|line| line.badge == badge) else {
            return;
        };
        let line = &mut self.held[index];
        if line.used > 0 {
            put_line(ports, &line.bytes[..line.used]);
            line.used = 0;
        }
        // The slot is given back, so a program that writes once and goes away
        // does not hold one for ever against callers that are still here.
        line.badge = 0;
    }

    /// Appends `bytes`, putting whole lines as their newlines arrive.
    fn append(&mut self, ports: &Ports, badge: u64, bytes: &[u8]) {
        let Some(line) = self.slot(badge) else {
            // No slot: this caller is not buffered at all, which is exactly
            // what every caller got before RFC 0052 -- and filtered strictly,
            // because a chunk on its own cannot see a colour sequence whole.
            let mut strict = [0u8; CHUNK_BYTES];
            let length = bytes.len().min(CHUNK_BYTES);
            for (out, byte) in strict.iter_mut().zip(&bytes[..length]) {
                *out = printable(*byte);
            }
            (ports.put_run)(&strict[..length]);
            return;
        };
        for byte in bytes {
            line.bytes[line.used] = *byte;
            line.used += 1;
            // A newline ends a line; a full buffer ends one whether the caller
            // meant it to or not, so that a program writing without newlines
            // gets its output in pieces rather than never.
            if *byte == b'\n' || line.used == LINE_BYTES {
                put_line(ports, &line.bytes[..line.used]);
                line.used = 0;
            }
        }
        // **Nothing held, so nothing to hold a slot for.** Until 2026-10-19 a
        // slot was given back only by `flush`, which only a *read* calls -- so
        // every caller that writes whole lines and never reads, which is most
        // services and every package, kept its slot for the rest of the boot.
        // Four of them took all four, and from then on every writer went
        // straight through in sixteen-byte chunks: typed at a release-built
        // machine with a disk and a network, `pkg run hello` printed
        // `namaste from an   it ended cleaninstalled packagly`. A slot now
        // means a partial line is pending, which is what it was for. Freed only
        // at the end of a chunk, so a newline in the middle of one cannot hand
        // the slot to another caller while this one still has bytes coming.
        if line.used == 0 {
            line.badge = 0;
        }
    }
}

/// A byte as the console may show it on its own: printable, space, newline or
/// tab, and `?` for anything else.
fn printable(byte: u8) -> u8 {
    match byte {
        b if b.is_ascii_graphic() || b == b' ' => b,
        b'\n' | b'\t' => byte,
        _ => b'?',
    }
}

/// The SGR parameters that may pass: reset, bold, dim, normal weight, and the
/// eight, default and bright colours, foreground and background. Nothing that
/// blinks, hides, reverses or moves anything.
fn colour_parameter(value: u16) -> bool {
    matches!(value, 0..=2 | 22 | 30..=37 | 39 | 40..=47 | 49 | 90..=97 | 100..=107)
}

/// The length of a colour sequence starting at `bytes[0]`, if one does: a
/// complete `ESC [ params m` whose parameters are all [`colour_parameter`]s
/// and at most sixteen bytes long. `None` for anything else, including a
/// sequence the line ends in the middle of.
fn colour_at(bytes: &[u8]) -> Option<usize> {
    const MOST: usize = 16;
    if bytes.len() < 3 || bytes[0] != 0x1b || bytes[1] != b'[' {
        return None;
    }
    let params_end = bytes[2..]
        .iter()
        .take(MOST + 1)
        .position(|byte| !(byte.is_ascii_digit() || *byte == b';'))?
        + 2;
    if params_end - 2 > MOST || bytes[params_end] != b'm' {
        return None;
    }
    let mut value: u16 = 0;
    let mut digits = 0;
    for byte in &bytes[2..params_end] {
        if *byte == b';' {
            if !colour_parameter(value) {
                return None;
            }
            value = 0;
            digits = 0;
        } else {
            digits += 1;
            if digits > 3 {
                return None;
            }
            value = value * 10 + u16::from(byte - b'0');
        }
    }
    colour_parameter(value).then_some(params_end + 1)
}

/// A held line as it may reach the kernel's console, into `out`; returns the
/// length.
///
/// **Colour and nothing else** -- the lead's decision of 2026-10-19, amending
/// RFC 0052. Printable bytes, newline and tab pass; a complete colour sequence
/// passes whole; every other byte that is not printable becomes `?`, and the
/// text of a refused sequence shows. A line that set a colour ends by resetting
/// it, before its newline, so a program cannot print the kernel's next line in
/// its colour. Checked here, on the whole line, because the caller's `write`
/// cuts a line into sixteen-byte chunks and a sequence is routinely split.
fn sanitize(line: &[u8], out: &mut [u8; LINE_BYTES + RESET.len()]) -> usize {
    let mut length = 0;
    let mut coloured = false;
    let mut at = 0;
    while at < line.len() {
        if let Some(sequence) = colour_at(&line[at..]) {
            out[length..length + sequence].copy_from_slice(&line[at..at + sequence]);
            length += sequence;
            at += sequence;
            coloured = true;
        } else {
            out[length] = printable(line[at]);
            length += 1;
            at += 1;
        }
    }
    if coloured {
        let newline = length > 0 && out[length - 1] == b'\n';
        let reset_at = if newline { length - 1 } else { length };
        out.copy_within(reset_at..length, reset_at + RESET.len());
        out[reset_at..reset_at + RESET.len()].copy_from_slice(RESET);
        length += RESET.len();
    }
    length
}

/// What ends a coloured line.
const RESET: &[u8] = b"\x1b[0m";

/// Puts one held line, sanitised. One `PUT_RUN` unless a reset pushed a full
/// line past `MAX_CONSOLE_RUN`, when the tail goes in a second.
fn put_line(ports: &Ports, line: &[u8]) {
    let mut out = [0u8; LINE_BYTES + RESET.len()];
    let length = sanitize(line, &mut out);
    let first = length.min(LINE_BYTES);
    (ports.put_run)(&out[..first]);
    if length > first {
        (ports.put_run)(&out[first..length]);
    }
}

impl Default for Lines {
    fn default() -> Self {
        Self::new()
    }
}

/// The console.
pub struct Console;

impl Service for Console {
    type Context = Ports;

    /// Partial lines, one per caller — RFC 0052.
    ///
    /// This was `()` until 2026-08-27, on the grounds that *"the console's state
    /// is the hardware's"*. That is still true of the hardware; what is held
    /// here is a decision about *when* to hand bytes to it, which is policy and
    /// belongs in the service rather than the nucleus.
    type State = Lines;

    const NAME: &'static str = "console";

    fn start(_ports: Self::Context) -> Result<Self::State, StartError> {
        Ok(Lines::new())
    }

    fn handle(lines: &mut Self::State, ports: &Self::Context, request: Request<'_>) -> Reply {
        match request.method {
            console::WRITE => Reply::new(write(lines, ports, request.badge, request.args)),
            // **Flush before reading, and this is the flush that matters.** A
            // shell writes `bhaskix$ ` with no newline and then waits for a
            // key: a discipline that only flushed on newlines would swallow
            // every prompt on the machine. It is what makes this a terminal
            // discipline rather than a buffer.
            console::READ => {
                lines.flush(ports, request.badge);
                Reply::new(read(ports))
            }
            console::RECORD_SIZE => Reply::new([(ports.record_size)() as u64, 0, 0, 0]),
            console::RECORD => Reply::new(record(ports, request.args)),
            // **Three words in one reply, because a shell asking "did anything
            // arrive?" should not have to ask three times.** The nucleus limit
            // is one word per call; a reply carries four, so the aggregation
            // belongs here rather than in every caller.
            console::STATS => Reply::new([
                (ports.input_stats)(0),
                (ports.input_stats)(1),
                (ports.input_stats)(2),
                0,
            ]),
            _ => Reply::new([with_outcome(0, outcome::WRONG_KIND), 0, 0, 0]),
        }
    }
}

/// Prints a caller's bytes, and says how many were accepted.
fn write(lines: &mut Lines, ports: &Ports, badge: u64, args: &[u64; 4]) -> [u64; 4] {
    let chunk = Chunk::unpack(args);

    // This is the *kernel's* console: a program that could emit an escape
    // sequence here could clear the screen, move the cursor, or print a line
    // that looks like it came from the kernel. So what a program writes is
    // filtered -- printable bytes, newline and tab, and since 2026-10-19 colour
    // and nothing else -- and a whole line crosses in one `PUT_RUN`, so a kernel
    // line printed on another CPU cannot land inside it (2026-08-27).
    //
    // Into the caller's held line rather than straight out -- RFC 0052 -- and
    // **filtered when the line is put, not here** (2026-10-19). Until then each
    // chunk was filtered on the way in, which kept every escape off the console
    // and also kept every colour off it: a colour sequence split across two
    // chunks was never whole in either. The line is checked whole now, by
    // `sanitize`, which passes colour and nothing else; a caller with no held
    // line is still filtered strictly, chunk by chunk, in `append`.
    lines.append(ports, badge, &chunk.bytes()[..chunk.len()]);

    [chunk.len() as u64, 0, 0, 0]
}

/// Waits for something to be typed and hands it back.
fn read(ports: &Ports) -> [u64; 4] {
    // Block for the first byte, then take whatever else is already waiting.
    // Returning one byte per message would be correct and would cost a round
    // trip per keystroke; taking the rest costs nothing and matters when a
    // terminal pastes a line.
    let mut bytes = [0u8; CHUNK_BYTES];
    bytes[0] = (ports.read)();
    let mut length = 1;
    while length < bytes.len() {
        match (ports.try_read)() {
            Some(byte) => {
                bytes[length] = byte;
                length += 1;
            }
            None => break,
        }
    }

    let (chunk, _) = Chunk::take(&bytes[..length]);
    chunk.pack(0)
}

/// Answers one chunk of the boot report, from the offset the caller asked for.
///
/// **A short chunk means the end, and an empty one means past it.** The caller
/// asked [`console::RECORD_SIZE`] first, so it already knows where the end is;
/// this being consistent with that is a second statement of the same fact, and
/// a caller that trusted only one of them would still stop in the right place.
fn record(ports: &Ports, args: &[u64; 4]) -> [u64; 4] {
    let offset = args[0] as usize;
    let size = (ports.record_size)();
    let remaining = size.saturating_sub(offset);
    let wanted = remaining.min(CHUNK_BYTES);

    let mut bytes = [0u8; CHUNK_BYTES];
    let mut filled = 0;
    while filled < wanted {
        let eight = (ports.record_at)(offset + filled);
        let take = (wanted - filled).min(8);
        bytes[filled..filled + take].copy_from_slice(&eight[..take]);
        filled += take;
    }
    let (chunk, _) = Chunk::take(&bytes[..filled]);
    chunk.pack(size as u64)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::vec::Vec;

    use bhaskix_abi::{outcome, outcome_of};
    use bhaskix_service::{Request, Service};

    use super::{Chunk, Console, LINE_BYTES, Lines, Ports, console};

    /// What the fake console has been shown, and what it will hand back.
    ///
    /// A static because [`Ports`] holds function pointers, which cannot
    /// capture — the same constraint the real placement has, so the fake is
    /// wired up the way the kernel is rather than a more convenient way.
    static PUT: Mutex<String> = Mutex::new(String::new());
    static TYPED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    /// Held by every test that touches the globals below, one at a time.
    ///
    /// **Added 2026-08-27, after writing a test that failed once and passed on
    /// the re-run.** `PUT` and `TYPED` are process-wide and cargo runs these in
    /// parallel: a test that clears `PUT` and then asserts on its contents is
    /// racing every other test that writes to it. The tests that existed before
    /// had the same hazard and had not been caught by it, which is how a race
    /// waits. `notify`'s test module learned this the same way and its comment
    /// says so.
    static SERIALISE: Mutex<()> = Mutex::new(());

    fn alone() -> MutexGuard<'static, ()> {
        SERIALISE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A poisoned lock is recovered rather than unwrapped: the workspace
    /// denies `unwrap` everywhere including tests, and here that lint is
    /// right for the ordinary reason — a failing assertion inside the guard
    /// would otherwise turn every later test in the file into a second
    /// failure that says nothing.
    fn held<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the kernel is pretending to have printed. RFC 0042.
    static RECORD: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    fn ports() -> Ports {
        Ports {
            put: |character| held(&PUT).push(character),
            // Through the same recorder, so the filtering test below still sees
            // what a caller managed to put -- and it is one call now, which is
            // the point of the change it is testing.
            put_run: |bytes| {
                let mut put = held(&PUT);
                for byte in bytes {
                    put.push(char::from(*byte));
                }
            },
            read: || held(&TYPED).remove(0),
            try_read: || {
                let mut typed = held(&TYPED);
                (!typed.is_empty()).then(|| typed.remove(0))
            },
            // Distinguishable per selector, so a test can tell "the three words
            // came back in order" from "three words came back".
            input_stats: |which| 0x1000 + which,
            record_size: || held(&RECORD).len(),
            record_at: |offset| {
                let record = held(&RECORD);
                let mut out = [0u8; 8];
                if offset < record.len() {
                    let end = (offset + 8).min(record.len());
                    out[..end - offset].copy_from_slice(&record[offset..end]);
                }
                out
            },
        }
    }

    fn request(method: u64, args: &[u64; 4]) -> Request<'_> {
        Request {
            method,
            args,
            badge: 1,
        }
    }

    /// The same, from a named caller — RFC 0052 keys held lines by badge.
    fn request_from(badge: u64, method: u64, args: &[u64; 4]) -> Request<'_> {
        Request {
            method,
            args,
            badge,
        }
    }

    /// Writes `text` as one caller, through the discipline.
    fn write_as(lines: &mut Lines, badge: u64, text: &[u8]) {
        let (chunk, _) = Chunk::take(text);
        Console::handle(
            lines,
            &ports(),
            request_from(badge, console::WRITE, &chunk.pack(0)),
        );
    }

    /// **A partial line is held, and a newline sends it.**
    ///
    /// The defect this exists for: a native program's line reached the console
    /// one 16-byte chunk at a time, and a kernel line printed on another CPU
    /// could land between two of them.
    #[test]
    fn a_line_without_a_newline_is_held_until_it_has_one() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        write_as(&mut lines, 7, b"sup: star");
        assert!(
            held(&PUT).is_empty(),
            "a partial line must not reach the console, or there was nothing to fix"
        );

        write_as(&mut lines, 7, b"ting\n");
        assert_eq!(
            *held(&PUT),
            "sup: starting\n",
            "the newline sends everything held, in one piece and in order"
        );
    }

    /// **Two callers do not join each other's lines**, which would be a worse
    /// fault than the interleaving being fixed.
    #[test]
    fn two_callers_hold_their_lines_apart() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        write_as(&mut lines, 7, b"first");
        write_as(&mut lines, 9, b"second\n");
        assert_eq!(
            *held(&PUT),
            "second\n",
            "the caller that finished its line is the only one that appears"
        );

        write_as(&mut lines, 7, b"\n");
        assert_eq!(
            *held(&PUT),
            "second\nfirst\n",
            "and the other follows, whole"
        );
    }

    /// **Callers that wrote whole lines and never read do not use up the
    /// slots.** The boot of 2026-10-19, in miniature: four services each write
    /// a line and never read, then a package and the shell write the lines that
    /// came out interleaved, in the very pieces they arrived in -- sixteen-byte
    /// chunks, each caller's interrupted by the other's.
    #[test]
    fn whole_lines_free_their_slot_for_the_next_caller() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        for badge in 1..=4 {
            write_as(&mut lines, badge, b"service ready\n");
        }
        held(&PUT).clear();

        write_as(&mut lines, 7, b"namaste from an ");
        write_as(&mut lines, 9, b"  it ended clean");
        write_as(&mut lines, 7, b"installed packag");
        write_as(&mut lines, 9, b"ly\n");
        write_as(&mut lines, 7, b"e\n");
        assert_eq!(
            *held(&PUT),
            "  it ended cleanly\nnamaste from an installed package\n",
            "each line whole, in the order they ended -- not the chunks interleaved"
        );
    }

    /// **A caller that never writes a newline is not held for ever.**
    #[test]
    fn a_full_line_goes_out_without_waiting_for_a_newline() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        // `Chunk` carries sixteen bytes, so this takes several writes.
        let mut sent = 0;
        while sent < LINE_BYTES {
            write_as(&mut lines, 7, &[b'x'; 16]);
            sent += 16;
        }
        assert_eq!(
            held(&PUT).len(),
            LINE_BYTES,
            "a full buffer must go out on its own, or a program with no newlines is silent"
        );
    }

    /// **A read flushes the reader's own line**, which is what keeps a prompt
    /// visible: a shell writes `bhaskix$ ` with no newline and then waits.
    #[test]
    fn a_read_flushes_the_readers_prompt_and_nobody_elses() {
        let _alone = alone();
        held(&PUT).clear();
        held(&TYPED).push(b'k');
        let mut lines = Lines::new();

        write_as(&mut lines, 7, b"bhaskix$ ");
        write_as(&mut lines, 9, b"other");
        assert!(held(&PUT).is_empty(), "neither has a newline yet");

        Console::handle(
            &mut lines,
            &ports(),
            request_from(7, console::READ, &[0; 4]),
        );
        assert_eq!(
            *held(&PUT),
            "bhaskix$ ",
            "the reader's prompt appears, and the other caller's line stays held"
        );
    }

    /// **Colour passes, whole, and never outlives its line** — the lead's
    /// decision of 2026-10-19, amending RFC 0052. The shell's `write` cuts a
    /// line into sixteen-byte chunks, so a colour sequence is routinely split
    /// in two; it is checked where the caller's whole line is held, and a line
    /// that set a colour ends by resetting it, so the kernel's next line is not
    /// printed in a program's colour.
    #[test]
    fn colour_split_across_chunks_arrives_whole_and_is_reset() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        // `  \x1b[1;32minstalled\x1b[0m  /pkg/hello`, as the shell sends it:
        // the first chunk ends inside the word, the second inside nothing, and
        // a sequence starts in one chunk and ends in the next.
        write_as(&mut lines, 7, b"  \x1b[1;32minstall");
        write_as(&mut lines, 7, b"ed\x1b[0m  /pkg/hel");
        write_as(&mut lines, 7, b"lo \x1b[9");
        write_as(&mut lines, 7, b"3mnew\n");
        assert_eq!(
            *held(&PUT),
            "  \x1b[1;32minstalled\x1b[0m  /pkg/hello \x1b[93mnew\x1b[0m\n",
            "every colour whole, including the one split across two chunks, and a reset before the newline"
        );
    }

    /// **Colour, and nothing else.** A clear, a cursor move, blink and
    /// conceal are refused whole — the sequence becomes `?` and its text is
    /// shown, as before 2026-10-19 — and so is a sequence the line ended in
    /// the middle of.
    #[test]
    fn only_colour_passes_and_a_cut_sequence_does_not() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        write_as(&mut lines, 7, b"\x1b[2J\x1b[H\x1b[5m");
        write_as(&mut lines, 7, b"x\x1b[1;8my\x1b[31\n");
        assert_eq!(
            *held(&PUT),
            "?[2J?[H?[5mx?[1;8my?[31\n",
            "a clear, a cursor move, blink, conceal mixed with bold, and an unfinished colour: all refused"
        );
    }

    /// **A caller with no held line gets no colour.** The fifth caller writes
    /// straight through, a chunk at a time, and a chunk cannot see a sequence
    /// whole -- so it keeps the strict filter it always had.
    #[test]
    fn a_caller_with_no_held_line_is_filtered_strictly() {
        let _alone = alone();
        held(&PUT).clear();
        let mut lines = Lines::new();

        for badge in 1..=4 {
            write_as(&mut lines, badge, b"partial ");
        }
        write_as(&mut lines, 9, b"\x1b[31mred\n");
        assert_eq!(
            *held(&PUT),
            "?[31mred\n",
            "every holder is taken by a partial line, so the fifth caller's colour is refused"
        );
    }

    #[test]
    fn a_caller_cannot_put_an_escape_sequence_on_the_kernels_console() {
        let _alone = alone();
        // The reason the filter exists: this is the kernel's console, and a
        // program that could emit an escape could clear the screen or print a
        // line that looks like the kernel printed it. Before the extraction
        // this could only be tested by booting a machine.
        held(&PUT).clear();
        let (chunk, _) = bhaskix_abi::Chunk::take(b"\x1b[2J\x07ok\n");
        let accepted = Console::handle(
            &mut Lines::new(),
            &ports(),
            request(bhaskix_abi::console::WRITE, &chunk.pack(0)),
        );

        assert_eq!(accepted.args[0], 8, "every byte is accounted for");
        assert_eq!(
            held(&PUT).as_str(),
            "?[2J?ok\n",
            "the escape and the bell are neutered; the newline is not"
        );
    }

    #[test]
    fn a_read_takes_what_is_waiting_and_stops() {
        let _alone = alone();
        // One round trip per keystroke would be correct and slow, so a read
        // drains what is already there -- and must stop at the end of it
        // rather than blocking again on a byte nobody typed.
        *held(&TYPED) = b"hi".to_vec();
        let reply = Console::handle(
            &mut Lines::new(),
            &ports(),
            request(bhaskix_abi::console::READ, &[0; 4]),
        );

        let chunk = bhaskix_abi::Chunk::unpack(&reply.args);
        assert_eq!(chunk.bytes(), b"hi");
        assert!(held(&TYPED).is_empty());
    }

    #[test]
    fn an_unknown_method_is_answered_rather_than_fatal() {
        let _alone = alone();
        // RFC 0013's fourth rule. A service is reachable by anything holding
        // its capability, so "the caller sent nonsense" has to be an outcome.
        let reply = Console::handle(&mut Lines::new(), &ports(), request(0xdead_beef, &[0; 4]));
        assert_eq!(outcome_of(reply.args[0]), outcome::WRONG_KIND);
    }

    /// The boot report, served back a chunk at a time. RFC 0042.
    #[test]
    fn the_record_is_served_a_chunk_at_a_time_and_ends_where_it_ends() {
        let _alone = alone();
        {
            let mut record = held(&RECORD);
            record.clear();
            record.extend_from_slice(b"boot report line one\nline two\n");
        }
        let ports = ports();
        let size = held(&RECORD).len();

        // The size is asked before anything is read, because a zero byte is a
        // byte somebody could have printed and cannot mean "the end".
        let reply = Console::handle(
            &mut Lines::new(),
            &ports,
            request(console::RECORD_SIZE, &[0; 4]),
        );
        assert_eq!(reply.args[0] as usize, size);

        // Reassembled a chunk at a time, exactly as a caller would.
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < size {
            let args = [offset as u64, 0, 0, 0];
            let reply = Console::handle(&mut Lines::new(), &ports, request(console::RECORD, &args));
            let chunk = Chunk::unpack(&reply.args);
            assert!(
                !chunk.bytes().is_empty(),
                "a chunk before the end must carry bytes, or the caller loops for ever"
            );
            out.extend_from_slice(chunk.bytes());
            offset += chunk.bytes().len();
        }
        assert_eq!(out, b"boot report line one\nline two\n");

        // Past the end is empty rather than an error, so a caller that trusted
        // the chunks alone stops where one that trusted the size does.
        let args = [size as u64, 0, 0, 0];
        let reply = Console::handle(&mut Lines::new(), &ports, request(console::RECORD, &args));
        assert!(Chunk::unpack(&reply.args).bytes().is_empty());
    }

    /// RFC 0051: the service's only job here is asking three times and putting
    /// all three in one reply, and this is that job.
    ///
    /// **In order, and that is the assertion.** The nucleus answers one word
    /// per call because a system call returns one; a caller that got the three
    /// words shuffled would read the keyboard's count as the serial's and
    /// conclude the opposite of the truth about a machine whose keyboard is in
    /// doubt.
    #[test]
    fn stats_asks_for_each_word_and_returns_them_in_order() {
        let _alone = alone();
        // No guard: this port is a pure function of its selector and touches
        // none of the shared state the other tests take turns over.
        let reply = Console::handle(
            &mut Lines::new(),
            &ports(),
            request(console::STATS, &[0; 4]),
        );
        assert_eq!(
            [reply.args[0], reply.args[1], reply.args[2]],
            [0x1000, 0x1001, 0x1002],
            "each word must come from its own selector, in order"
        );
    }
}
