// SPDX-License-Identifier: Apache-2.0
//! The seeded mutation harness `docs/coding-style.md` §8 requires.
//!
//! Deterministic, on stable, in CI, on every build, in milliseconds. The four
//! libFuzzer targets in `fuzz/` are the other line of defence and neither
//! replaces the other: coverage guidance finds what blind mutation cannot, and
//! blind mutation runs on every commit without a nightly toolchain.
//!
//! # The harness is told where the edges are
//!
//! §8 records what this project learned the expensive way: *a mutation harness
//! tests the middle of the input space unless it is told where the edges are.*
//! A wrapping bounds check in the ELF parser survived half a million uniform
//! mutations, because reaching it needed an offset within sixteen of
//! `u64::MAX` — about one draw in 2^60.
//!
//! Network headers have their own edges and they are not the same ones, so
//! [`EDGE16`] is drawn from explicitly and the mutators target length and
//! offset fields rather than scattering bytes.
//!
//! # What the edge list is actually worth here, measured
//!
//! **Less than it is for the ELF loader, and this is written down rather than
//! assumed.** The guard that refuses a UDP length below its own header was
//! removed on purpose, together with the bounds-checked read that follows it,
//! and the harness caught the resulting panic — `range end index 6 out of range
//! for slice of length 0`, which is exactly the case the list exists for.
//!
//! Then the edge list was disabled and the same bug was hunted with uniform
//! 16-bit draws only. **It was still caught at 20,000 seeds** — and at 200,000
//! and 2,000,000. The arithmetic says why: a length field is 16 bits and the
//! bug needs any of eight values, so a uniform draw finds it about one time in
//! 8,192, and each seed makes several draws. That is nothing like the ELF
//! parser's wrapping check, which needed an offset within sixteen of
//! `u64::MAX` — one draw in 2^60 — and survived half a million mutations.
//!
//! The list is kept, because it costs a branch and the ELF experience is that
//! *some* bugs are unreachable without it. But the honest claim is narrower
//! than "the edges are why this works": for the 16-bit fields in these headers,
//! blind mutation reaches the edges on its own. A future 32-bit field, or a
//! check that fires only at one exact value, is where this list will earn its
//! place — and whoever adds one should repeat this measurement rather than
//! inherit this paragraph's conclusion.

use crate::{
    addr::{Address, Ipv4Addr, MacAddr, Port},
    arp::ArpPacket,
    checksum,
    eth::{self, EthFrame, EtherType},
    icmp,
    ipv4::{self, Ipv4Header, Protocol, Reassembly},
    tcp::{
        FourTuple, Sequence,
        segment::{self, Flags, Options, Segment},
        state::{self, Actions, Event, Tcb, Timer},
    },
    udp::{self, UdpDatagram},
};

/// The same deterministic generator every other harness in this tree uses.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    /// A 16-bit value, half the time from the edges rather than uniformly.
    fn edged16(&mut self) -> u16 {
        if self.next() & 1 == 0 {
            EDGE16[self.below(EDGE16.len())]
        } else {
            self.next() as u16
        }
    }
}

/// The 16-bit values that break length arithmetic in these headers.
///
/// Zero and one because a length below its own header is what makes a
/// subtraction wrap. The header sizes and their neighbours because that is
/// where "at least" and "more than" differ. `u16::MAX` and its neighbour
/// because that is the largest a length field can claim, and a buffer never
/// holds it. `0x8000` because a sign bit set is what a widening conversion
/// mishandles.
const EDGE16: [u16; 14] = [
    0, 1, 7, 8, 9, 19, 20, 21, 27, 28, 0x7fff, 0x8000, 0xfffe, 0xffff,
];

const HERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const THERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const MINE: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const PEER: MacAddr = MacAddr([0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc]);

/// How many seeds to run, and where to start.
///
/// The same two variables the ELF and `ustar` harnesses read, so a batch runner
/// drives all of them the same way — and `SEED_BASE` matters for the same
/// reason it did there: without it a longer campaign re-tests what the last one
/// already cleared.
fn campaign() -> (u64, u64) {
    let iterations: u64 = std::env::var("BHASKIX_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000);
    let first: u64 = std::env::var("BHASKIX_FUZZ_SEED_BASE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (first, iterations)
}

fn rng_for(seed: u64) -> Rng {
    Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(7))
}

/// A well-formed Ethernet frame carrying `payload` as `ethertype`.
fn frame(ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; eth::HEADER + payload.len()];
    eth::write_header(&mut bytes, MINE, PEER, ethertype).unwrap();
    bytes[eth::HEADER..].copy_from_slice(payload);
    bytes
}

/// A well-formed IPv4 datagram, checksum repaired.
fn ipv4(payload: &[u8], identification: u16, offset: usize, more: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; ipv4::HEADER + payload.len()];
    let total = bytes.len();
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&identification.to_be_bytes());
    let flags = if more { 0x2000u16 } else { 0 };
    bytes[6..8].copy_from_slice(&(flags | (offset / 8) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = ipv4::Protocol::UDP.0;
    bytes[12..16].copy_from_slice(&HERE.octets());
    bytes[16..20].copy_from_slice(&THERE.octets());
    bytes[ipv4::HEADER..].copy_from_slice(payload);
    repair_ipv4(&mut bytes);
    bytes
}

/// Recomputes an IPv4 header checksum in place.
///
/// **Without this the campaign fuzzes the doorway.** §8 records the same lesson
/// from `DMAR`: a parser guarded by a checksum is unreachable to a fuzzer that
/// does not repair it, and a target that does not say so reports a clean run
/// over the first check. Half the seeds below repair and half do not, so both
/// the checksum path and everything behind it are exercised.
fn repair_ipv4(bytes: &mut [u8]) {
    if bytes.len() < ipv4::HEADER {
        return;
    }
    let words = usize::from(bytes[0] & 0x0f) * 4;
    let length = if (ipv4::HEADER..=bytes.len()).contains(&words) {
        words
    } else {
        ipv4::HEADER
    };
    bytes[10..12].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&bytes[..length]]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
}

/// Applies `count` mutations, biased towards the fields that carry lengths.
fn mutate(rng: &mut Rng, bytes: &mut [u8], count: usize) {
    if bytes.is_empty() {
        return;
    }
    for _ in 0..count {
        match rng.below(4) {
            // A single byte anywhere. The classic, and the weakest.
            0 => {
                let index = rng.below(bytes.len());
                bytes[index] = rng.next() as u8;
            }
            // A whole 16-bit field, from the edge list half the time. This is
            // the mutation that reaches a length of zero or 0xffff, which a
            // byte flip essentially never does.
            1 if bytes.len() >= 2 => {
                let index = rng.below(bytes.len() - 1);
                bytes[index..index + 2].copy_from_slice(&rng.edged16().to_be_bytes());
            }
            // The first four bytes, where version, IHL and the high half of
            // every total length live.
            2 => {
                let index = rng.below(4.min(bytes.len()));
                bytes[index] = rng.next() as u8;
            }
            // A run, so that several fields move together -- the case a
            // single-site mutator cannot produce.
            _ => {
                let start = rng.below(bytes.len());
                let run = 1 + rng.below(8.min(bytes.len() - start));
                for byte in &mut bytes[start..start + run] {
                    *byte = rng.next() as u8;
                }
            }
        }
    }
}

/// Truncates to a random prefix on some seeds.
///
/// Every parser here has a fixed header and a stated length, so the boundary
/// between "enough bytes" and "one fewer" is the most valuable place to be, and
/// mutation alone never moves the buffer's own length.
fn maybe_truncate(rng: &mut Rng, bytes: &mut Vec<u8>) {
    if rng.below(3) == 0 && !bytes.is_empty() {
        let length = rng.below(bytes.len());
        bytes.truncate(length);
    }
}

#[test]
fn ethernet_never_panics() {
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);
        let mut bytes = frame(EtherType::IPV4, &[0xaa; 46]);
        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        maybe_truncate(&mut rng, &mut bytes);
        // What it returns does not matter; that it returns does.
        if let Ok(parsed) = EthFrame::parse(&bytes) {
            let _ = parsed.addressed_to(MINE);
            assert!(parsed.payload.len() <= bytes.len());
        }
    }
}

#[test]
fn arp_never_panics() {
    let (first, iterations) = campaign();
    let template = ArpPacket {
        operation: crate::arp::ArpOp::Request,
        sender_hardware: PEER,
        sender_protocol: THERE,
        target_hardware: MacAddr::UNSPECIFIED,
        target_protocol: HERE,
    };
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);
        let mut bytes = vec![0u8; crate::arp::PACKET];
        template.write(&mut bytes).unwrap();
        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        maybe_truncate(&mut rng, &mut bytes);
        if let Ok(parsed) = ArpPacket::parse(&bytes) {
            // Feed what parsed into the cache: `learn` has its own refusals and
            // they are reachable only from a packet that got this far.
            let mut cache = crate::arp::ArpCache::<4>::new(1_000);
            let _ = cache.learn(parsed.sender_protocol, parsed.sender_hardware, seed);
            let _ = cache.lookup(parsed.sender_protocol, seed);
        }
    }
}

#[test]
fn ipv4_never_panics() {
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);
        let mut bytes = ipv4(&[0xbb; 32], 1, 0, false);
        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        // Half the seeds repair the checksum, so that the fields behind it are
        // reachable at all. The other half exercise the check itself.
        if seed & 1 == 0 {
            repair_ipv4(&mut bytes);
        }
        maybe_truncate(&mut rng, &mut bytes);
        if let Ok((header, payload)) = Ipv4Header::parse(&bytes) {
            assert!(header.header_length <= header.total_length);
            assert!(header.total_length <= bytes.len());
            assert_eq!(payload.len(), header.total_length - header.header_length);
        }
    }
}

#[test]
fn udp_never_panics() {
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);
        let mut bytes = vec![0u8; udp::HEADER + 24];
        udp::write(&mut bytes, Port(4242), Port(53), &[0xcc; 24], HERE, THERE).unwrap();
        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        maybe_truncate(&mut rng, &mut bytes);
        if let Ok(parsed) = UdpDatagram::parse(&bytes, HERE, THERE) {
            assert!(parsed.payload.len() + udp::HEADER <= bytes.len());
        }
    }
}

#[test]
fn reassembly_never_panics_and_never_exceeds_its_table() {
    // The stateful one, and the most valuable: the table is the only thing here
    // that a remote party can drive across many packets rather than one. Each
    // seed offers a burst of mutated fragments to one table and requires that
    // it stays inside its own bounds throughout.
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations / 4).max(first + 1) {
        let mut rng = rng_for(seed);
        let mut table = Reassembly::<4, 256>::new(1_000);

        for step in 0..12u64 {
            let offset = rng.below(64) * 8;
            let more = rng.next() & 1 == 0;
            let length = rng.below(40);
            let mut bytes = ipv4(&vec![0xdd; length], (seed % 4) as u16, offset, more);
            let count = rng.below(3);
            mutate(&mut rng, &mut bytes, count);
            if seed & 1 == 0 {
                repair_ipv4(&mut bytes);
            }

            let now = step * 100;
            if let Ok((header, payload)) = Ipv4Header::parse(&bytes)
                && let Ok(Some(index)) = table.offer(&header, payload, now)
            {
                let assembled = table.assembled(index).expect("complete means assembled");
                assert!(assembled.len() <= 256);
                table.release(index);
            }
            assert!(table.in_flight() <= 4, "the table grew past its capacity");
        }
    }
}

/// Recomputes a TCP checksum in place, over the pseudo-header and the segment.
///
/// **Without this the campaign fuzzes the checksum and nothing else.** Every
/// interesting field in a TCP header — the data offset, and the whole option
/// walk behind it — sits after the checksum test, so a mutated segment that is
/// not repaired is refused at the door. The same lesson `DMAR` taught and
/// `ipv4` records above, and it costs more here than anywhere else in this file
/// because what is behind the door is a loop.
fn repair_tcp(bytes: &mut [u8]) {
    if bytes.len() < segment::HEADER {
        return;
    }
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&HERE.octets());
    pseudo[4..8].copy_from_slice(&THERE.octets());
    pseudo[9] = Protocol::TCP.0;
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    pseudo[10..12].copy_from_slice(&length.to_be_bytes());
    bytes[16..18].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&pseudo, bytes]);
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn tcp_never_panics() {
    // The option walk is the reason this target exists. Every other parser in
    // this crate reads a fixed layout; this one loops with a stride a remote
    // party chooses, and a stride of zero is a hang rather than a misparse.
    //
    // So the seed alternates between a plain segment and one carrying options,
    // and the mutator is pointed at the option area as well as the header —
    // otherwise the walk is reached with the same four well-formed bytes every
    // time and the loop is never driven at all.
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);

        let payload = [0xf0u8; 16];
        let mut template = Segment {
            source: Port(49152),
            destination: Port(80),
            sequence: Sequence(0x1000_0000),
            acknowledgement: Some(Sequence(0x2000_0000)),
            flags: Flags::PSH,
            window: 4096,
            options: Options::default(),
            payload: &payload,
        };
        if seed & 2 == 0 {
            template.options.mss = Some(1460);
        }
        let mut bytes = vec![0u8; segment::HEADER + 8 + payload.len()];
        let written = segment::write(&mut bytes, &template, HERE, THERE).unwrap();
        bytes.truncate(written);

        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        // Byte 12's top nibble is the data offset, and it decides both where
        // the payload begins and how much of the segment the option walk reads.
        // A general mutator lands on it about one time in twenty; this makes it
        // one time in three, because it is the field everything else derives
        // from.
        if rng.below(3) == 0 && bytes.len() > 12 {
            bytes[12] = (rng.next() as u8) & 0xf0;
        }
        // Half the seeds repair, so the fields behind the checksum are
        // reachable at all; the other half exercise the check itself.
        if seed & 1 == 0 {
            repair_tcp(&mut bytes);
        }
        maybe_truncate(&mut rng, &mut bytes);

        if let Ok(parsed) = Segment::parse(&bytes, HERE, THERE) {
            // A payload cannot exceed the segment it was cut from, and the data
            // offset is the only thing that decides where it starts -- so this
            // is what a mis-checked offset would break while still returning
            // `Ok`.
            assert!(parsed.payload.len() + segment::HEADER <= bytes.len());
            // A SYN and a FIN each occupy a number, so this is bounded by the
            // payload plus two and can never be less than the payload.
            let space = parsed.sequence_length();
            assert!(space >= parsed.payload.len() as u32);
            assert!(space <= parsed.payload.len() as u32 + 2);
            // The flag and the field agree in both directions, which is the
            // invariant `parse` establishes and `write` preserves.
            assert_eq!(
                parsed.acknowledgement.is_some(),
                parsed.flags.contains(Flags::ACK)
            );
        }
    }
}

/// Everything that must be true of a control block after any event whatsoever.
///
/// RFC 0020's testing plan names three; the other two are here because they are
/// free once the harness exists.
fn invariants(tcb: &Tcb, actions: &Actions) {
    assert!(!actions.overflowed(), "the action list overflowed");
    assert!(
        !tcb.snd_una.follows(tcb.snd_nxt),
        "snd.una ran ahead of snd.nxt: {:?}",
        tcb
    );
    assert!(
        tcb.rcv_wnd <= tcb.rcv_capacity,
        "the window advertised more room than the program's ring holds"
    );
    // **The machine must never name bytes the program did not supply.** One
    // past `snd_avail` is the `FIN`, which occupies a sequence number and is
    // not a byte of the ring. Anything beyond that is `bin/tcpd` being told to
    // read past what the program wrote and put it on the wire — a disclosure,
    // not a bookkeeping error, which is why this is asserted rather than
    // assumed from `snd_nxt`'s arithmetic looking right.
    assert!(
        !tcb.snd_nxt.follows(tcb.snd_avail.wrapping_add(1)),
        "snd.nxt ran past the bytes the program supplied: {tcb:?}"
    );
    assert!(
        (state::MIN_RTO_US..=state::MAX_RTO_US).contains(&tcb.rto_us),
        "the retransmission timeout left its bounds: {}",
        tcb.rto_us
    );
    assert!(tcb.retransmits <= state::MAX_RETRANSMITS);
}

#[test]
fn the_tcp_state_machine_never_panics_and_holds_its_invariants() {
    // **The target RFC 0020 says matters**, and the one that is different in
    // kind from every other harness here: the others forget each input as they
    // finish with it, and this one carries state between inputs that a remote
    // party chose. A segment is only interesting in the light of the twenty
    // before it.
    //
    // The sequence numbers are drawn *near* `rcv_nxt` half the time rather than
    // uniformly, for the same reason the checksum is repaired elsewhere in this
    // file: a uniform 32-bit draw is outside the receive window essentially
    // always, so an unbiased campaign would test the acceptability check and
    // nothing behind it. That is the doorway lesson for a third time, in the
    // one place where the door leads to a state machine.
    let (first, iterations) = campaign();
    let payload = [0x5au8; 600];

    for seed in first..first.saturating_add(iterations / 2).max(first + 1) {
        let mut rng = rng_for(seed);
        let connection = FourTuple {
            local: Address::V4(HERE),
            local_port: Port(49152),
            remote: Address::V4(THERE),
            remote_port: Port(80),
        };
        let mut tcb = Tcb::new(connection);
        let mut now = 0u64;

        let opening = if seed & 1 == 0 {
            Event::Connect {
                iss: Sequence(rng.next() as u32),
                window: rng.edged16(),
            }
        } else {
            Event::Listen {
                iss: Sequence(rng.next() as u32),
                window: rng.edged16(),
            }
        };
        let (next, actions) = state::step(tcb, opening, now);
        tcb = next;
        invariants(&tcb, &actions);

        for _ in 0..24 {
            now = now.saturating_add(u64::from(rng.edged16()) * 1_000_000);
            let event = match rng.below(8) {
                0 => Event::Wrote(u32::from(rng.edged16())),
                1 => Event::Read(u32::from(rng.edged16())),
                2 => Event::Shutdown,
                3 => Event::Expired(
                    [
                        Timer::Retransmit,
                        Timer::DelayedAck,
                        Timer::Probe,
                        Timer::TimeWait,
                    ][rng.below(4)],
                ),
                // Abort is deliberately rare: it closes the connection, and a
                // run that aborts on its second event tests almost nothing.
                4 if rng.below(8) == 0 => Event::Abort,
                _ => {
                    // Half plausible, half arbitrary.
                    let sequence = if rng.next() & 1 == 0 {
                        tcb.rcv_nxt.wrapping_add(rng.below(8) as u32)
                    } else {
                        Sequence(rng.next() as u32)
                    };
                    let acknowledgement = match rng.below(4) {
                        0 => None,
                        1 => Some(Sequence(rng.next() as u32)),
                        _ => Some(tcb.snd_nxt.wrapping_add(rng.below(4) as u32)),
                    };
                    let length = rng.below(payload.len() + 1);
                    Event::Arrived(Segment {
                        source: Port(80),
                        destination: Port(49152),
                        sequence,
                        acknowledgement,
                        flags: Flags(rng.next() as u8),
                        window: rng.edged16(),
                        options: Options::default(),
                        payload: &payload[..length],
                    })
                }
            };
            let (next, actions) = state::step(tcb, event, now);
            tcb = next;
            invariants(&tcb, &actions);
        }
    }
}

#[test]
fn icmp_never_panics() {
    let (first, iterations) = campaign();
    for seed in first..first.saturating_add(iterations) {
        let mut rng = rng_for(seed);
        let mut bytes = vec![0u8; icmp::HEADER + 24];
        icmp::write(&mut bytes, false, 0x1234, 1, &[0xee; 24]).unwrap();
        let count = 1 + rng.below(6);
        mutate(&mut rng, &mut bytes, count);
        // Half the seeds repair the checksum, so the type and code checks
        // behind it are reachable at all; the other half exercise the check.
        if seed & 1 == 0 && bytes.len() >= icmp::HEADER {
            bytes[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum(&[&bytes]);
            bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        maybe_truncate(&mut rng, &mut bytes);
        if let Ok(parsed) = icmp::Echo::parse(&bytes) {
            assert!(parsed.payload.len() + icmp::HEADER <= bytes.len());
        }
    }
}
