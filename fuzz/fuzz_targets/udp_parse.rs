// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the UDP parser.
//!
//! Eight bytes, one of which is a length that a receiver must not subtract from
//! before checking. A stated length of zero is the value that turns
//! `stated - HEADER` into 65,528, and it is one draw in 8,192 for a blind
//! mutator — findable, but only if something is drawing.
//!
//! # The checksum is optional, which doubles the state space
//!
//! Over IPv4 a sender may send zero instead of computing one. So there are
//! three outcomes rather than two — verified, absent, and wrong — and the
//! absent path skips the whole pseudo-header computation. A campaign that only
//! ever produced checksummed datagrams would leave that path uncovered, and a
//! campaign that only ever produced zeros would never reach the arithmetic.
//! Random bytes produce both, which is the one thing this target does not have
//! to arrange for itself.
//!
//! # The addresses are inputs, not constants
//!
//! The checksum covers a pseudo-header built from the IP source and
//! destination, so the same bytes verify at one address pair and fail at
//! another. Both are driven from the input here rather than fixed, because a
//! parser that ignored the pseudo-header would pass a campaign that always
//! passed it the same two addresses.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run udp_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::Ipv4Addr,
    udp::{self, UdpDatagram},
};

fuzz_target!(|data: &[u8]| {
    // The first eight bytes choose the address pair, so one input covers both
    // "the pseudo-header matched" and "it did not". The rest is the datagram.
    let (addresses, bytes) = data.split_at(data.len().min(8));
    let mut pair = [0u8; 8];
    pair[..addresses.len()].copy_from_slice(addresses);
    let source = Ipv4Addr(u32::from_be_bytes([pair[0], pair[1], pair[2], pair[3]]));
    let destination = Ipv4Addr(u32::from_be_bytes([pair[4], pair[5], pair[6], pair[7]]));

    if let Ok(parsed) = UdpDatagram::parse(bytes, source, destination) {
        // A payload plus its header cannot exceed the input it came from, and
        // the length field is the only thing that decides where it ends -- so
        // this is the assertion that a mis-checked length would break while
        // still returning `Ok`.
        assert!(parsed.payload.len() + udp::HEADER <= bytes.len());

        // Round trip: what parsed must rebuild, and the rebuilt datagram must
        // parse again to the same payload. This reaches the writer, which is
        // otherwise only covered by host tests with well-formed input.
        let mut out = [0u8; 2048];
        if let Ok(written) = udp::write(
            &mut out,
            parsed.source,
            parsed.destination,
            parsed.payload,
            source,
            destination,
        ) {
            let again = UdpDatagram::parse(&out[..written], source, destination)
                .expect("a datagram this code wrote must parse");
            assert_eq!(again.payload, parsed.payload);
            assert_eq!(again.source, parsed.source);
            assert_eq!(again.destination, parsed.destination);
            // The writer always computes a checksum, so the round trip must
            // come back checked even when the input was not.
            assert!(again.checksummed);
        }
    }
});
