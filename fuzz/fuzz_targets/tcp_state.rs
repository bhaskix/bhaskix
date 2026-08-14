// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the TCP state machine.
//!
//! # This is the only target here whose subject remembers anything
//!
//! Every other target in this directory parses an input and forgets it. `elf`,
//! `ustar`, `DMAR`, and the five network parsers all answer one question about
//! one buffer. This one drives a *sequence* of events into a control block that
//! carries sequence numbers, windows, timers and a state across all of them —
//! so the interesting inputs are not malformed segments but **orders**: a `RST`
//! after a `FIN` but before its acknowledgement, a window that closes and
//! reopens between two retransmissions, a `SYN` arriving in `TIME_WAIT`.
//!
//! That is exactly the shape coverage guidance is for. A blind mutator will
//! never assemble a twelve-event sequence that reaches `CLOSING`; a fuzzer that
//! is told which inputs found new code will.
//!
//! # The input is a script, and sequence numbers are drawn near the window
//!
//! Bytes are consumed as opcodes and operands. Sequence numbers are taken
//! *relative to* what the connection currently expects about half the time,
//! because a uniform 32-bit draw is outside the receive window essentially
//! always — an unbiased campaign would spend itself on the acceptability check
//! and never reach the machine behind it. That is the same lesson `DMAR` taught
//! about checksums, in the one place where the door leads to a state machine.
//!
//! # What is asserted
//!
//! No panic, and the invariants RFC 0020's testing plan names: `snd.una` never
//! runs ahead of `snd.nxt`, the advertised window never exceeds the program's
//! ring, and — the one that is a disclosure rather than a bookkeeping error —
//! `snd.nxt` never runs past the bytes the program actually supplied.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run tcp_state -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::{Address, Ipv4Addr, Port},
    tcp::{
        FourTuple, Sequence,
        segment::{Flags, Options, Segment},
        state::{self, Actions, Event, Tcb, Timer},
    },
};

/// A reader over the input, which never runs out — it returns zeroes instead.
///
/// A script that ended by returning `None` would make every short input take a
/// different path from every long one, and the corpus would fill with length
/// variations rather than event orders.
struct Script<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Script<'a> {
    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        value
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    fn exhausted(&self) -> bool {
        self.at >= self.bytes.len()
    }
}

/// Everything that must hold after any event at all.
fn invariants(tcb: &Tcb, actions: &Actions) {
    assert!(!actions.overflowed(), "the action list overflowed");
    assert!(
        !tcb.snd_una.follows(tcb.snd_nxt),
        "snd.una ran ahead of snd.nxt: {tcb:?}"
    );
    assert!(
        tcb.rcv_wnd <= tcb.rcv_capacity,
        "the window advertised more room than the ring holds: {tcb:?}"
    );
    assert!(
        !tcb.snd_nxt.follows(tcb.snd_avail.wrapping_add(1)),
        "snd.nxt ran past the bytes the program supplied: {tcb:?}"
    );
    assert!(
        (state::MIN_RTO_US..=state::MAX_RTO_US).contains(&tcb.rto_us),
        "the retransmission timeout left its bounds: {tcb:?}"
    );
    assert!(tcb.retransmits <= state::MAX_RETRANSMITS);
}

/// The payload every arriving segment borrows from. Contents do not matter —
/// this machine never looks at a byte of application data, which is the design
/// decision the whole module rests on.
const PAYLOAD: [u8; 2048] = [0x5a; 2048];

fuzz_target!(|data: &[u8]| {
    let mut script = Script { bytes: data, at: 0 };

    let connection = FourTuple {
        local: Address::V4(Ipv4Addr::new(10, 0, 2, 15)),
        local_port: Port(49152),
        remote: Address::V4(Ipv4Addr::new(10, 0, 2, 2)),
        remote_port: Port(80),
    };
    let mut tcb = Tcb::new(connection);
    let mut now: u64 = 0;

    // Open actively or passively, which decides which half of the state graph
    // is reachable at all.
    let opening = if script.byte() & 1 == 0 {
        Event::Connect {
            iss: Sequence(script.u32()),
            window: script.u16(),
        }
    } else {
        Event::Listen {
            iss: Sequence(script.u32()),
            window: script.u16(),
        }
    };
    let (next, actions) = state::step(tcb, opening, now);
    tcb = next;
    invariants(&tcb, &actions);

    // Bounded so a long input cannot make one execution dominate the campaign.
    for _ in 0..64 {
        if script.exhausted() {
            break;
        }
        now = now.saturating_add(u64::from(script.u16()) * 1_000_000);

        let event = match script.byte() % 8 {
            0 => Event::Wrote(u32::from(script.u16())),
            1 => Event::Read(u32::from(script.u16())),
            2 => Event::Shutdown,
            3 => Event::Abort,
            4 => Event::Expired(
                [
                    Timer::Retransmit,
                    Timer::DelayedAck,
                    Timer::Probe,
                    Timer::TimeWait,
                ][usize::from(script.byte() % 4)],
            ),
            _ => {
                let control = script.byte();
                // Relative to what the connection expects, or arbitrary. The
                // relative case is what reaches the machine; the arbitrary case
                // is what tests the acceptability check that guards it.
                let sequence = if control & 1 == 0 {
                    tcb.rcv_nxt.wrapping_add(u32::from(script.u16()))
                } else {
                    Sequence(script.u32())
                };
                let acknowledgement = match control >> 1 & 3 {
                    0 => None,
                    1 => Some(Sequence(script.u32())),
                    _ => Some(tcb.snd_nxt.wrapping_add(u32::from(script.byte()))),
                };
                let length = usize::from(script.u16()) % (PAYLOAD.len() + 1);
                Event::Arrived(Segment {
                    source: Port(80),
                    destination: Port(49152),
                    sequence,
                    acknowledgement,
                    flags: Flags(script.byte()),
                    window: script.u16(),
                    options: Options {
                        mss: (control & 0x80 != 0).then(|| script.u16()),
                    },
                    payload: &PAYLOAD[..length],
                })
            }
        };

        let (next, actions) = state::step(tcb, event, now);
        tcb = next;
        invariants(&tcb, &actions);
    }
});
