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
    /// port's: `write` maps each byte through the same substitution it always
    /// did before handing the run over, so a program still cannot put an escape
    /// sequence on the kernel's console.
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

/// The console.
pub struct Console;

impl Service for Console {
    type Context = Ports;

    /// Nothing. The console's state is the hardware's, and the hardware is on
    /// the far side of [`Ports`].
    type State = ();

    const NAME: &'static str = "console";

    fn start(_ports: Self::Context) -> Result<Self::State, StartError> {
        Ok(())
    }

    fn handle((): &mut Self::State, ports: &Self::Context, request: Request<'_>) -> Reply {
        match request.method {
            console::WRITE => Reply::new(write(ports, request.args)),
            console::READ => Reply::new(read(ports)),
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
fn write(ports: &Ports, args: &[u64; 4]) -> [u64; 4] {
    let chunk = Chunk::unpack(args);

    // Filtered, exactly as the kernel shell filters what it prints. This is
    // the *kernel's* console: a program that could emit an escape sequence
    // here could clear the screen, move the cursor, or print a line that looks
    // like it came from the kernel. Newline and tab pass through, because
    // without them nothing can be laid out.
    // **Filtered into a buffer, then put in one go.** The filtering is
    // unchanged and still happens here; what changed on 2026-08-27 is that the
    // whole chunk crosses in a single invocation, so a kernel line printed on
    // another CPU cannot land between two of its bytes.
    //
    // **A chunk and not a line**, which is the honest limit: `CHUNK_BYTES` is
    // 16, so a longer write is several messages and they can still be
    // separated. What this removes is the fifteen gaps *inside* each of them.
    let mut filtered = [0u8; bhaskix_abi::CHUNK_BYTES];
    for (out, byte) in filtered.iter_mut().zip(chunk.bytes()) {
        *out = match byte {
            b if b.is_ascii_graphic() || *b == b' ' => *byte,
            b'\n' | b'\t' => *byte,
            _ => b'?',
        };
    }
    (ports.put_run)(&filtered[..chunk.len()]);

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

    use super::{Chunk, Console, Ports, console};

    /// What the fake console has been shown, and what it will hand back.
    ///
    /// A static because [`Ports`] holds function pointers, which cannot
    /// capture — the same constraint the real placement has, so the fake is
    /// wired up the way the kernel is rather than a more convenient way.
    static PUT: Mutex<String> = Mutex::new(String::new());
    static TYPED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

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

    #[test]
    fn a_caller_cannot_put_an_escape_sequence_on_the_kernels_console() {
        // The reason the filter exists: this is the kernel's console, and a
        // program that could emit an escape could clear the screen or print a
        // line that looks like the kernel printed it. Before the extraction
        // this could only be tested by booting a machine.
        held(&PUT).clear();
        let (chunk, _) = bhaskix_abi::Chunk::take(b"\x1b[2J\x07ok\n");
        let accepted = Console::handle(
            &mut (),
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
        // One round trip per keystroke would be correct and slow, so a read
        // drains what is already there -- and must stop at the end of it
        // rather than blocking again on a byte nobody typed.
        *held(&TYPED) = b"hi".to_vec();
        let reply = Console::handle(
            &mut (),
            &ports(),
            request(bhaskix_abi::console::READ, &[0; 4]),
        );

        let chunk = bhaskix_abi::Chunk::unpack(&reply.args);
        assert_eq!(chunk.bytes(), b"hi");
        assert!(held(&TYPED).is_empty());
    }

    #[test]
    fn an_unknown_method_is_answered_rather_than_fatal() {
        // RFC 0013's fourth rule. A service is reachable by anything holding
        // its capability, so "the caller sent nonsense" has to be an outcome.
        let reply = Console::handle(&mut (), &ports(), request(0xdead_beef, &[0; 4]));
        assert_eq!(outcome_of(reply.args[0]), outcome::WRONG_KIND);
    }

    /// The boot report, served back a chunk at a time. RFC 0042.
    #[test]
    fn the_record_is_served_a_chunk_at_a_time_and_ends_where_it_ends() {
        {
            let mut record = held(&RECORD);
            record.clear();
            record.extend_from_slice(b"boot report line one\nline two\n");
        }
        let ports = ports();
        let size = held(&RECORD).len();

        // The size is asked before anything is read, because a zero byte is a
        // byte somebody could have printed and cannot mean "the end".
        let reply = Console::handle(&mut (), &ports, request(console::RECORD_SIZE, &[0; 4]));
        assert_eq!(reply.args[0] as usize, size);

        // Reassembled a chunk at a time, exactly as a caller would.
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < size {
            let args = [offset as u64, 0, 0, 0];
            let reply = Console::handle(&mut (), &ports, request(console::RECORD, &args));
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
        let reply = Console::handle(&mut (), &ports, request(console::RECORD, &args));
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
        // No guard: this port is a pure function of its selector and touches
        // none of the shared state the other tests take turns over.
        let reply = Console::handle(&mut (), &ports(), request(console::STATS, &[0; 4]));
        assert_eq!(
            [reply.args[0], reply.args[1], reply.args[2]],
            [0x1000, 0x1001, 0x1002],
            "each word must come from its own selector, in order"
        );
    }
}
