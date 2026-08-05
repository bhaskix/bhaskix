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
    /// Waits for a byte to be typed, and returns it.
    pub read: fn() -> u8,
    /// Takes a byte if one is already waiting, without blocking.
    pub try_read: fn() -> Option<u8>,
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
    for byte in chunk.bytes() {
        let character = match byte {
            b if b.is_ascii_graphic() || *b == b' ' => *byte as char,
            b'\n' | b'\t' => *byte as char,
            _ => '?',
        };
        (ports.put)(character);
    }

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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::vec::Vec;

    use bhaskix_abi::{outcome, outcome_of};
    use bhaskix_service::{Request, Service};

    use super::{Console, Ports};

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

    fn ports() -> Ports {
        Ports {
            put: |character| held(&PUT).push(character),
            read: || held(&TYPED).remove(0),
            try_read: || {
                let mut typed = held(&TYPED);
                (!typed.is_empty()).then(|| typed.remove(0))
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
}
