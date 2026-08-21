// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the TCP segment parser and its option walk.
//!
//! # This is the first parser in this project with a loop in it
//!
//! Every other target here reads a fixed layout: a length is checked, a slice
//! is taken, the parser returns. The TCP option list is a walk whose *stride*
//! comes out of the packet — an option says how long it is, and the walk
//! believes it in order to find the next one. A length of zero does not advance,
//! and the classic consequence is not a misparse but a service that never
//! answers again.
//!
//! Coverage guidance matters more here than for the datagram parsers for that
//! reason: reaching a particular arrangement of options — an unknown kind, then
//! a NOP, then a maximum segment size that runs one byte past the header —
//! needs several bytes to line up, which is precisely what blind mutation does
//! not do and what the seeded harness in `net/src/fuzz.rs` records itself as
//! bad at.
//!
//! # The checksum has to be repaired or this fuzzes the doorway
//!
//! `DMAR` taught this project the lesson and `ipv4_parse` restates it: a parser
//! behind a whole-input checksum is unreachable to a fuzzer that does not
//! repair one. Here it costs more than usual, because everything worth reaching
//! is behind it. So each input is parsed twice — once as supplied, which
//! exercises the checksum test itself, and once with the checksum repaired,
//! which is the only way the option walk is reached at all.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run tcp_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::{Address, Ipv4Addr},
    checksum,
    ipv4::Protocol,
    tcp::{
        Flags,
        segment::{self, Segment},
    },
};

/// Recomputes the checksum over the pseudo-header and the segment.
/// Still `Ipv4Addr`-shaped: the stack's own `pseudo_of` is private, and this
/// helper builds the v4 pseudo-header by hand. RFC 0029 gave TCP a second
/// family and a **mixed-family refusal** that nothing here exercises — a v6
/// arm for this target is the coverage-guided IPv6 work TRACKER §4 tracks.
fn repair(bytes: &mut [u8], source: Ipv4Addr, destination: Ipv4Addr) {
    if bytes.len() < segment::HEADER {
        return;
    }
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&source.octets());
    pseudo[4..8].copy_from_slice(&destination.octets());
    pseudo[9] = Protocol::TCP.0;
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    pseudo[10..12].copy_from_slice(&length.to_be_bytes());
    bytes[16..18].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&pseudo, bytes]);
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
}

/// Everything asserted about a segment that parsed.
///
/// Written once and applied to both parses, so the repaired path and the
/// as-supplied path are held to the same standard rather than the repaired one
/// being the only one checked.
fn check(parsed: &Segment<'_>, bytes: &[u8], source: Address, destination: Address) {
    // The data offset is the only field that decides where the payload starts,
    // so this is what a mis-checked offset breaks while still returning `Ok`.
    assert!(parsed.payload.len() + segment::HEADER <= bytes.len());

    // A SYN and a FIN each occupy one sequence number and nothing else does.
    let space = parsed.sequence_length();
    assert!(space >= parsed.payload.len() as u32);
    assert!(space <= parsed.payload.len() as u32 + 2);

    // The invariant `parse` establishes: the acknowledgement number exists
    // exactly when the flag that makes it meaningful is set.
    assert_eq!(
        parsed.acknowledgement.is_some(),
        parsed.flags.contains(Flags::ACK)
    );

    // Round trip, which is the only thing that reaches the writer with input a
    // human did not choose. What parsed must rebuild, and the rebuilt segment
    // must parse again to the same thing -- note that the two need not be
    // byte-identical, because options this stack does not implement are walked
    // correctly and then not written back.
    let mut out = [0u8; 2048];
    if let Ok(written) = segment::write(&mut out, parsed, source, destination) {
        let again = Segment::parse(&out[..written], source, destination)
            .expect("a segment this code wrote must parse");
        assert_eq!(&again, parsed);
    }
}

fuzz_target!(|data: &[u8]| {
    // The first eight bytes choose the address pair, so one input covers both
    // "the pseudo-header matched" and "it did not". The rest is the segment.
    let (addresses, bytes) = data.split_at(data.len().min(8));
    let mut pair = [0u8; 8];
    pair[..addresses.len()].copy_from_slice(addresses);
    // `Address`, not `Ipv4Addr`: RFC 0029 step 5 took TCP across families, so
    // the checksum functions take the family-agnostic address. **This target
    // did not compile from 2026-08-18 until 2026-08-21** and ran no executions
    // at all in that window — see the module comment.
    let source_v4 = Ipv4Addr(u32::from_be_bytes([pair[0], pair[1], pair[2], pair[3]]));
    let destination_v4 = Ipv4Addr(u32::from_be_bytes([pair[4], pair[5], pair[6], pair[7]]));
    let source = Address::V4(source_v4);
    let destination = Address::V4(destination_v4);

    // As supplied: mostly this exercises the checksum test, which is the one
    // check a repaired input can never fail.
    if let Ok(parsed) = Segment::parse(bytes, source, destination) {
        check(&parsed, bytes, source, destination);
    }

    // Repaired: this is the pass that reaches the data offset and the option
    // walk. Without it the campaign reports clean coverage of a closed door.
    let mut repaired = bytes.to_vec();
    repair(&mut repaired, source_v4, destination_v4);
    if let Ok(parsed) = Segment::parse(&repaired, source, destination) {
        check(&parsed, &repaired, source, destination);
    }
});
